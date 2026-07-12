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
        Self::connect_handle(StreamHandle::from_stream(stream), options).await
    }

    /// Connect to a radio on a USB-serial port (e.g. `/dev/ttyUSB0`,
    /// `/dev/ttyACM0`). `baud` defaults to the standard Meshtastic serial
    /// rate when `None`.
    pub async fn connect_serial(
        port: &str,
        baud: Option<u32>,
        options: MeshtasticOptions,
    ) -> Result<Self> {
        let handle =
            meshtastic::utils::stream::build_serial_stream(port.to_owned(), baud, None, None)
                .map_err(link_error)?;
        Self::connect_handle(handle, options).await
    }

    /// Connect to a radio's network API (`host:4403` on Wi-Fi/Ethernet
    /// radios, or anything speaking the same framed protocol).
    pub async fn connect_tcp(address: &str, options: MeshtasticOptions) -> Result<Self> {
        let handle = meshtastic::utils::stream::build_tcp_stream(address.to_owned())
            .await
            .map_err(link_error)?;
        Self::connect_handle(handle, options).await
    }

    async fn connect_handle<S>(handle: StreamHandle<S>, options: MeshtasticOptions) -> Result<Self>
    where
        S: AsyncReadExt + AsyncWriteExt + Send + 'static,
    {
        let started = Instant::now();
        let (mut packets, api) = StreamApi::new().connect(handle).await;
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

    fn broadcast_hint(&self) -> Option<DeliveryHint> {
        Some(DeliveryHint::MeshNode(MESH_BROADCAST))
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

/// A faithful in-memory fake radio for tests: speaks the framed Meshtastic
/// client protocol on any byte stream, answers the `want_config_id`
/// handshake, and floods packets over a shared "air" hub. Used by this
/// crate's integration tests and by `kultd`'s mesh end-to-end test; not
/// part of the supported API.
#[doc(hidden)]
pub mod testutil {
    use meshtastic::protobufs::{self, config, from_radio, to_radio};
    use meshtastic::Message as _;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
    use tokio::sync::broadcast;

    /// The shared RF medium: (transmitting radio's node number, packet).
    pub type Air = broadcast::Sender<(u32, protobufs::MeshPacket)>;

    /// What the fake radio reports in its configuration handshake.
    #[derive(Clone, Copy, Debug)]
    pub struct RadioSpec {
        /// The radio's node number.
        pub node_num: u32,
        /// LoRa modem preset (`ModemPreset` as i32).
        pub modem_preset: i32,
        /// Regulatory region (`RegionCode` as i32).
        pub region: i32,
    }

    impl RadioSpec {
        /// The common test radio: LongFast in the US region (no duty-cycle
        /// budget), so tests exercise delivery, not airtime limits.
        pub fn unbudgeted(node_num: u32) -> Self {
            use config::lo_ra_config::{ModemPreset, RegionCode};
            Self {
                node_num,
                modem_preset: ModemPreset::LongFast as i32,
                region: RegionCode::Us as i32,
            }
        }
    }

    /// Frame one `FromRadio` for the wire: `0x94 0xc3 len_msb len_lsb body`.
    pub fn frame(msg: &protobufs::FromRadio) -> Vec<u8> {
        let body = msg.encode_to_vec();
        let mut out = vec![
            0x94,
            0xc3,
            (body.len() >> 8) as u8,
            (body.len() & 0xff) as u8,
        ];
        out.extend_from_slice(&body);
        out
    }

    /// Extract one framed payload from `buf`, resyncing on the magic bytes
    /// the way real firmware does.
    fn next_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        loop {
            while !buf.is_empty() && buf[0] != 0x94 {
                buf.remove(0);
            }
            if buf.len() >= 2 && buf[1] != 0xc3 {
                buf.remove(0);
                continue;
            }
            if buf.len() < 4 {
                return None;
            }
            let len = usize::from(buf[2]) << 8 | usize::from(buf[3]);
            if buf.len() < 4 + len {
                return None;
            }
            let body = buf[4..4 + len].to_vec();
            buf.drain(..4 + len);
            return Some(body);
        }
    }

    fn handshake_replies(spec: &RadioSpec, config_id: u32) -> Vec<protobufs::FromRadio> {
        let lora = config::LoRaConfig {
            use_preset: true,
            modem_preset: spec.modem_preset,
            region: spec.region,
            tx_enabled: true,
            ..Default::default()
        };
        [
            from_radio::PayloadVariant::MyInfo(protobufs::MyNodeInfo {
                my_node_num: spec.node_num,
                ..Default::default()
            }),
            from_radio::PayloadVariant::Config(protobufs::Config {
                payload_variant: Some(config::PayloadVariant::Lora(lora)),
            }),
            from_radio::PayloadVariant::ConfigCompleteId(config_id),
        ]
        .into_iter()
        .map(|payload_variant| protobufs::FromRadio {
            id: 0,
            payload_variant: Some(payload_variant),
        })
        .collect()
    }

    /// Serve one client connection as a stock-firmware-shaped radio:
    /// answers the config handshake, transmits client packets onto the
    /// `air` hub, and delivers other radios' packets up to the client.
    /// Runs until the stream closes.
    pub async fn serve_stream<S>(spec: RadioSpec, air: Air, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let mut from_air = air.subscribe();
        let (mut rx, mut tx) = tokio::io::split(stream);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            tokio::select! {
                read = rx.read(&mut chunk) => {
                    let Ok(n) = read else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(body) = next_frame(&mut buf) {
                        let Ok(to_radio) = protobufs::ToRadio::decode(&body[..]) else {
                            continue;
                        };
                        match to_radio.payload_variant {
                            Some(to_radio::PayloadVariant::WantConfigId(id)) => {
                                for msg in handshake_replies(&spec, id) {
                                    if tx.write_all(&frame(&msg)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Some(to_radio::PayloadVariant::Packet(packet)) => {
                                // Errors just mean nobody is listening on air.
                                let _ = air.send((spec.node_num, packet));
                            }
                            _ => {} // Heartbeats etc.
                        }
                    }
                }
                received = from_air.recv() => {
                    let Ok((from_node, packet)) = received else { return };
                    if from_node == spec.node_num {
                        continue; // A radio does not hear its own transmission.
                    }
                    let msg = protobufs::FromRadio {
                        id: 0,
                        payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
                    };
                    if tx.write_all(&frame(&msg)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Spawn a fake radio on an in-memory duplex; returns the client side.
    pub fn spawn_duplex(spec: RadioSpec, air: Air) -> DuplexStream {
        let (client_side, radio_side) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve_stream(spec, air, radio_side));
        client_side
    }

    /// Spawn a fake radio serving connections on a TCP listener (what
    /// `MeshtasticTransport::connect_tcp` dials in tests).
    pub fn spawn_tcp(spec: RadioSpec, air: Air, listener: tokio::net::TcpListener) {
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_stream(spec, air.clone(), stream));
            }
        });
    }
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
