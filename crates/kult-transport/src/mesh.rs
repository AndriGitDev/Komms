//! Meshtastic LoRa carrier (docs/05-transports.md §4, ADR-0005).
//!
//! Speaks the standard Meshtastic client protocol — protobufs over the
//! framed stream every stock-firmware radio exposes on USB-serial, TCP and
//! BLE — via the official `meshtastic` client crate. No custom firmware:
//! owning any supported radio is the only hardware requirement.
//!
//! Contract compliance (docs/05-transports.md §1):
//! - **Ciphertext only**: sealed [`Envelope`]s travel as opaque bytes on a
//!   dedicated private application port ([`PortNum::PrivateApp`]);
//!   Meshtastic's own channel encryption is an untrusted outer wrapper.
//! - **No identity leakage**: peers are addressed by Meshtastic node number
//!   ([`DeliveryHint::MeshNode`]) — a transport pseudonym. Recipients
//!   recognize their traffic by delivery token, so the normal mode is
//!   mesh-wide flooding to [`MESH_BROADCAST`] (§4.2 rule 4).
//! - **Honest signals**: a send resolves to [`SendReceipt::HandedToLink`]
//!   once the radio has the frame; nothing more is claimed. Airtime refusals
//!   surface as [`TransportError::AirtimeExhausted`] instead of silently
//!   queueing into a duty-cycle violation.
//!
//! The frame budget is computed at runtime from what the radio reports: the
//! protobuf-pinned `Data.payload` capacity (233 B) is the envelope MTU, and
//! the radio's LoRa config (modem preset, region) drives per-frame
//! time-on-air and the regulatory duty-cycle budget ([`crate::airtime`]).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use meshtastic::api::{state, ConnectedStreamApi, StreamApi, StreamHandle};
use meshtastic::packet::PacketReceiver;
use meshtastic::protobufs::config::lo_ra_config::{ModemPreset, RegionCode};
use meshtastic::protobufs::{self, config, from_radio, mesh_packet, to_radio, PortNum};
use meshtastic::utils::generate_rand_id;
use meshtastic::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use kult_protocol::Envelope;

use crate::airtime::{time_on_air, AirtimeBudget, ModemParams, DUTY_CYCLE_WINDOW};
use crate::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, Result, SendReceipt,
    Transport, TransportError,
};

/// The Meshtastic broadcast node number. `DeliveryHint::MeshNode(MESH_BROADCAST)`
/// floods within normal Meshtastic routing; KommsKult recipients pick out
/// envelopes whose delivery tokens they recognize (§4.2 rule 4).
pub const MESH_BROADCAST: u32 = u32::MAX;

/// Envelope bytes per LoRa frame: the `Data.payload` capacity pinned by the
/// Meshtastic protobufs (`Constants::DataPayloadLen`). Larger envelopes are
/// fragmented by the delivery engine before reaching [`Transport::send`].
const MESH_MTU: usize = protobufs::Constants::DataPayloadLen as usize;

/// On-air bytes in front of the encrypted protobuf payload: the fixed
/// Meshtastic packet header (destination, sender, id, flags, hash, next-hop,
/// relay-node — 16 bytes on every LoRa frame).
const PACKET_HEADER_LEN: usize = 16;

/// Meshtastic's default LoRa preamble length in symbols.
const PREAMBLE_SYMBOLS: u16 = 16;

/// Connection options for [`MeshtasticTransport::connect`].
#[derive(Clone, Copy, Debug)]
pub struct MeshtasticOptions {
    /// Meshtastic channel index to send on (0 = the device's primary
    /// channel). Which channel is irrelevant to security — the envelope is
    /// self-protecting — but determines which mesh neighbors rebroadcast.
    pub channel: u32,
    /// How long to wait for the radio's configuration handshake.
    pub config_timeout: Duration,
}

impl Default for MeshtasticOptions {
    fn default() -> Self {
        Self {
            channel: 0,
            config_timeout: Duration::from_secs(15),
        }
    }
}

/// State the sender path mutates under one lock: the stream client plus the
/// duty-cycle budget, so a reservation and its transmission are atomic.
struct Sender {
    api: ConnectedStreamApi<state::Configured>,
    budget: Option<AirtimeBudget>,
}

/// The Meshtastic carrier. See the module docs for the contract mapping.
pub struct MeshtasticTransport {
    sender: Mutex<Sender>,
    incoming: Mutex<PacketReceiver>,
    node_num: u32,
    channel: u32,
    params: ModemParams,
    started: Instant,
}

impl MeshtasticTransport {
    /// Connect over any byte stream a Meshtastic radio is reachable on —
    /// USB-serial, TCP (`host:4403`), or an in-memory duplex in tests.
    ///
    /// Performs the standard client handshake (`want_config_id`), harvests
    /// the radio's node number and LoRa config, and sizes the airtime
    /// budget from the radio's region: duty-limited regions (EU868 etc.)
    /// get a rolling-window budget, everything else transmits unbudgeted,
    /// mirroring the firmware's own regulatory table.
    pub async fn connect<S>(stream: S, options: MeshtasticOptions) -> Result<Self>
    where
        S: AsyncReadExt + AsyncWriteExt + Send + 'static,
    {
        let started = Instant::now();
        let (mut packets, api) = StreamApi::new()
            .connect(StreamHandle::from_stream(stream))
            .await;
        let config_id: u32 = generate_rand_id();
        let api = api.configure(config_id).await.map_err(link_error)?;

        let handshake = async {
            let mut node_num = None;
            let mut lora: Option<config::LoRaConfig> = None;
            while let Some(packet) = packets.recv().await {
                match packet.payload_variant {
                    Some(from_radio::PayloadVariant::MyInfo(info)) => {
                        node_num = Some(info.my_node_num);
                    }
                    Some(from_radio::PayloadVariant::Config(c)) => {
                        if let Some(config::PayloadVariant::Lora(l)) = c.payload_variant {
                            lora = Some(l);
                        }
                    }
                    Some(from_radio::PayloadVariant::ConfigCompleteId(id)) if id == config_id => {
                        return Some((node_num, lora));
                    }
                    _ => {}
                }
            }
            None
        };
        let Ok(Some((node_num, lora))) =
            tokio::time::timeout(options.config_timeout, handshake).await
        else {
            return Err(handshake_failed("radio configuration handshake timed out"));
        };
        let (Some(node_num), Some(lora)) = (node_num, lora) else {
            return Err(handshake_failed(
                "radio omitted node info or LoRa config from handshake",
            ));
        };

        let params = modem_params(&lora);
        let budget = match duty_cycle_percent(lora.region()) {
            100 => None,
            percent => Some(AirtimeBudget::new(percent, DUTY_CYCLE_WINDOW)),
        };

        Ok(Self {
            sender: Mutex::new(Sender { api, budget }),
            incoming: Mutex::new(packets),
            node_num,
            channel: options.channel,
            params,
            started,
        })
    }

    /// The radio's node number on the mesh (its transport pseudonym).
    pub fn node_num(&self) -> u32 {
        self.node_num
    }

    /// The modem parameters derived from the radio's config, as used for
    /// airtime accounting.
    pub fn modem_params(&self) -> ModemParams {
        self.params
    }
}

#[async_trait]
impl Transport for MeshtasticTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: MESH_MTU,
            latency: LatencyClass::Seconds,
            cost: CostClass::Airtime,
            broadcast: true,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            DeliveryHint::MeshNode(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(&self, peer: &DeliveryHint, envelope: &Envelope) -> Result<SendReceipt> {
        let DeliveryHint::MeshNode(destination) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        let encoded = envelope.encode();
        if encoded.len() > MESH_MTU {
            return Err(TransportError::Protocol(
                kult_protocol::ProtocolError::MtuTooSmall,
            ));
        }

        let data = protobufs::Data {
            portnum: PortNum::PrivateApp as i32,
            payload: encoded,
            ..Default::default()
        };

        let mut sender = self.sender.lock().await;
        if let Some(budget) = &mut sender.budget {
            // On-air frame = fixed packet header + the encoded Data proto
            // (Meshtastic's channel cipher preserves length).
            let frame_len = PACKET_HEADER_LEN + data.encoded_len();
            let airtime = time_on_air(&self.params, frame_len).ok_or_else(|| {
                handshake_failed("radio reported a modem config airtime cannot be computed for")
            })?;
            budget
                .try_reserve(airtime, self.started.elapsed())
                .map_err(|retry_after| TransportError::AirtimeExhausted { retry_after })?;
        }

        let packet = protobufs::MeshPacket {
            from: self.node_num,
            to: *destination,
            channel: self.channel,
            id: generate_rand_id(),
            // hop_limit 0 = "use the device's configured default".
            payload_variant: Some(mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        };
        sender
            .api
            .send_to_radio_packet(Some(to_radio::PayloadVariant::Packet(packet)))
            .await
            .map_err(link_error)?;
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        let mut incoming = self.incoming.lock().await;
        let mut out = Vec::new();
        while let Ok(packet) = incoming.try_recv() {
            let Some(from_radio::PayloadVariant::Packet(mesh)) = packet.payload_variant else {
                continue;
            };
            let Some(mesh_packet::PayloadVariant::Decoded(data)) = mesh.payload_variant else {
                continue;
            };
            if data.portnum != PortNum::PrivateApp as i32 {
                continue;
            }
            // The mesh is a public medium: anything undecodable on our port
            // is noise and is skipped, never an error.
            if let Ok(envelope) = Envelope::decode(&data.payload) {
                out.push(envelope);
            }
        }
        Ok(out)
    }
}

/// Modem parameters from the radio's LoRa config: the firmware's preset
/// table when `use_preset` is set, the explicit fields otherwise. Presets
/// this build doesn't know get the slowest table entry, so duty-cycle
/// accounting over-reserves rather than under-reserves (fail-safe).
fn modem_params(lora: &config::LoRaConfig) -> ModemParams {
    // Deprecated presets (LongSlow …) still exist on deployed radios; the
    // client must map whatever the radio reports.
    #[allow(deprecated)]
    let (bandwidth_hz, spreading_factor, coding_rate_denominator) = if lora.use_preset {
        match lora.modem_preset() {
            ModemPreset::ShortTurbo => (500_000, 7, 5),
            ModemPreset::ShortFast => (250_000, 7, 5),
            ModemPreset::ShortSlow => (250_000, 8, 5),
            ModemPreset::MediumFast => (250_000, 9, 5),
            ModemPreset::MediumSlow => (250_000, 10, 5),
            ModemPreset::LongFast => (250_000, 11, 5),
            ModemPreset::LongModerate => (125_000, 11, 8),
            ModemPreset::LongSlow => (125_000, 12, 8),
            // Not in this build's table (e.g. newer firmware presets):
            // assume the slowest known preset.
            _ => (62_500, 12, 8),
        }
    } else {
        (
            bandwidth_hz(lora.bandwidth),
            lora.spread_factor.clamp(0, u32::from(u8::MAX)) as u8,
            lora.coding_rate.clamp(0, u32::from(u8::MAX)) as u8,
        )
    };
    ModemParams {
        bandwidth_hz,
        spreading_factor,
        coding_rate_denominator,
        preamble_symbols: PREAMBLE_SYMBOLS,
    }
}

/// The config's `bandwidth` field is kHz with the fractional entries
/// truncated (31 → 31.25 kHz, 62 → 62.5 kHz).
fn bandwidth_hz(bandwidth_khz: u32) -> u32 {
    match bandwidth_khz {
        31 => 31_250,
        62 => 62_500,
        other => other.saturating_mul(1000),
    }
}

/// Regulatory duty-cycle percentage per region, mirroring the firmware's
/// region table: the EU and Ukraine 433/868 bands are duty-limited to 10 %
/// (Meshtastic's EU868 slot lives in the 869.4–869.65 MHz 10 % sub-band);
/// other regions are airtime-fair but not duty-capped.
fn duty_cycle_percent(region: RegionCode) -> u8 {
    match region {
        RegionCode::Eu433 | RegionCode::Eu868 | RegionCode::Ua433 | RegionCode::Ua868 => 10,
        _ => 100,
    }
}

fn link_error(e: meshtastic::errors::Error) -> TransportError {
    TransportError::Io(std::io::Error::other(e))
}

fn handshake_failed(msg: &'static str) -> TransportError {
    TransportError::Io(std::io::Error::other(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lora_with_preset(preset: ModemPreset, region: RegionCode) -> config::LoRaConfig {
        config::LoRaConfig {
            use_preset: true,
            modem_preset: preset as i32,
            region: region as i32,
            ..Default::default()
        }
    }

    #[test]
    fn preset_table_maps_long_fast() {
        let params = modem_params(&lora_with_preset(ModemPreset::LongFast, RegionCode::Eu868));
        assert_eq!(
            params,
            ModemParams {
                bandwidth_hz: 250_000,
                spreading_factor: 11,
                coding_rate_denominator: 5,
                preamble_symbols: 16,
            }
        );
    }

    #[test]
    fn unknown_preset_falls_back_to_slowest() {
        let params = modem_params(&lora_with_preset(ModemPreset::LongTurbo, RegionCode::Us));
        assert_eq!(params.spreading_factor, 12);
        assert_eq!(params.bandwidth_hz, 62_500);
    }

    #[test]
    fn explicit_fields_win_without_preset() {
        let lora = config::LoRaConfig {
            use_preset: false,
            bandwidth: 62,
            spread_factor: 9,
            coding_rate: 7,
            ..Default::default()
        };
        let params = modem_params(&lora);
        assert_eq!(params.bandwidth_hz, 62_500);
        assert_eq!(params.spreading_factor, 9);
        assert_eq!(params.coding_rate_denominator, 7);
    }

    #[test]
    fn duty_cycle_table() {
        assert_eq!(duty_cycle_percent(RegionCode::Eu868), 10);
        assert_eq!(duty_cycle_percent(RegionCode::Eu433), 10);
        assert_eq!(duty_cycle_percent(RegionCode::Us), 100);
        assert_eq!(duty_cycle_percent(RegionCode::Unset), 100);
    }

    /// A maximum-size frame exactly fills the 255-byte LoRa payload: 16 B
    /// packet header + 3 B portnum field + 3 B length-delimited tag/len +
    /// 233 B envelope.
    #[test]
    fn max_frame_fits_lora() {
        let data = protobufs::Data {
            portnum: PortNum::PrivateApp as i32,
            payload: vec![0u8; MESH_MTU],
            ..Default::default()
        };
        assert_eq!(PACKET_HEADER_LEN + data.encoded_len(), 255);
    }
}
