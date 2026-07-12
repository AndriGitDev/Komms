//! LoRa airtime accounting for the Meshtastic carrier
//! (docs/05-transports.md §4.2 rule 2/3, docs/08-roadmap.md M4).
//!
//! Airtime is the scarcest resource in the system, and several regulatory
//! regions cap it hard (EU868: 10 % duty cycle on the 869.4–869.65 MHz
//! sub-band Meshtastic transmits in). This module is deliberately pure —
//! integer math over caller-supplied clocks, no radio types, no I/O — so it
//! can be reviewed and tested as its own unit
//! (docs/09-implementation-guide.md §3.3).
//!
//! Time-on-air follows the Semtech LoRa modem formula (SX1276 datasheet
//! §4.1.1.7 / AN1200.13): with symbol time `Tsym = 2^SF / BW`,
//!
//! ```text
//! n_payload = 8 + max(ceil((8·PL − 4·SF + 28 + 16) / (4·(SF − 2·DE))) · CRden, 0)
//! ToA       = (n_preamble + 4.25 + n_payload) · Tsym
//! ```
//!
//! for explicit headers with CRC on (Meshtastic's configuration), where `DE`
//! is the low-data-rate optimization flag, auto-enabled — as RadioLib and
//! therefore Meshtastic firmware do — when the symbol time reaches 16.38 ms.

use std::collections::VecDeque;
use std::time::Duration;

/// Physical-layer parameters of one LoRa modem configuration. Constructed by
/// the Meshtastic carrier from the radio's reported config; kept free of
/// radio-crate types so the math stays independently reviewable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModemParams {
    /// Channel bandwidth in Hz (Meshtastic presets use 62 500–500 000).
    pub bandwidth_hz: u32,
    /// Spreading factor (7–12 across the Meshtastic presets).
    pub spreading_factor: u8,
    /// Coding-rate denominator: 5 for 4/5 … 8 for 4/8.
    pub coding_rate_denominator: u8,
    /// Preamble length in symbols (Meshtastic default: 16).
    pub preamble_symbols: u16,
}

impl ModemParams {
    /// Sanity-check the parameter ranges the formula is valid for.
    fn valid(&self) -> bool {
        (5..=12).contains(&self.spreading_factor)
            && (5..=8).contains(&self.coding_rate_denominator)
            && self.bandwidth_hz > 0
            && self.preamble_symbols > 0
    }

    /// Symbol duration in microseconds (exact for all Meshtastic bandwidths).
    fn symbol_micros(&self) -> u64 {
        ((1u64 << self.spreading_factor) * 1_000_000) / u64::from(self.bandwidth_hz)
    }
}

/// Symbol time at/above which low-data-rate optimization is enabled,
/// mirroring the RadioLib auto-enable rule Meshtastic firmware relies on.
const LOW_DATA_RATE_THRESHOLD_MICROS: u64 = 16_380;

/// Time on air of one LoRa frame of `payload_len` physical-layer payload
/// bytes (Meshtastic packet header + encrypted protobuf payload), rounded up
/// to whole microseconds. `None` for parameters outside the formula's valid
/// range — the caller must treat that as "cannot budget, do not send".
pub fn time_on_air(params: &ModemParams, payload_len: usize) -> Option<Duration> {
    if !params.valid() || payload_len > 255 {
        return None;
    }
    let sf = i64::from(params.spreading_factor);
    let de = i64::from(params.symbol_micros() >= LOW_DATA_RATE_THRESHOLD_MICROS);
    let cr_den = i64::from(params.coding_rate_denominator);

    // 8·PL − 4·SF + 28 + 16·CRC − 20·IH, CRC = 1, IH = 0 (explicit header).
    let numerator = 8 * payload_len as i64 - 4 * sf + 28 + 16;
    let denominator = 4 * (sf - 2 * de);
    if denominator <= 0 {
        return None; // SF5/SF6 with DE set never occurs on real presets.
    }
    // max(ceil(numerator / denominator) · CRden, 0): non-positive numerators
    // (tiny payloads at high SF) contribute no extra symbols.
    let extra_symbols = if numerator > 0 {
        (numerator as u64).div_ceil(denominator as u64) * cr_den as u64
    } else {
        0
    };
    let n_payload = 8 + extra_symbols;

    // Work in quarter-symbols so the preamble's +4.25 stays exact.
    let quarter_symbols = 4 * (u64::from(params.preamble_symbols) + n_payload) + 17;
    let micros = (quarter_symbols * params.symbol_micros()).div_ceil(4);
    Some(Duration::from_micros(micros))
}

/// Rolling-window duty-cycle budget with honest refusal.
///
/// The regulatory model: within any observation window (1 h here, matching
/// how EU duty limits are assessed), cumulative transmission time must not
/// exceed `limit_percent` of the window. [`AirtimeBudget::try_reserve`]
/// answers *before* the radio transmits; a refusal tells the caller when
/// retrying can succeed, and the delivery engine surfaces the wait instead
/// of silently hogging the mesh (docs/05-transports.md §4.2 rule 3).
///
/// Clocks are caller-supplied monotonic offsets so the accounting is exactly
/// testable; the carrier feeds it `Instant`-derived elapsed time.
#[derive(Debug)]
pub struct AirtimeBudget {
    limit_percent: u8,
    window: Duration,
    /// Accounted transmissions, oldest first: (accounted at, time on air).
    spent: VecDeque<(Duration, Duration)>,
}

/// The regulatory observation window duty limits are assessed over.
pub const DUTY_CYCLE_WINDOW: Duration = Duration::from_secs(3600);

impl AirtimeBudget {
    /// A budget allowing `limit_percent` of `window` as cumulative airtime.
    /// `limit_percent` is clamped to 1–100.
    pub fn new(limit_percent: u8, window: Duration) -> Self {
        Self {
            limit_percent: limit_percent.clamp(1, 100),
            window,
            spent: VecDeque::new(),
        }
    }

    fn allowance(&self) -> Duration {
        self.window.mul_f64(f64::from(self.limit_percent) / 100.0)
    }

    fn purge(&mut self, now: Duration) {
        let horizon = now.saturating_sub(self.window);
        while let Some(&(at, _)) = self.spent.front() {
            if at >= horizon {
                break;
            }
            self.spent.pop_front();
        }
    }

    /// Airtime still available at `now`.
    pub fn available(&mut self, now: Duration) -> Duration {
        self.purge(now);
        let used: Duration = self.spent.iter().map(|&(_, toa)| toa).sum();
        self.allowance().saturating_sub(used)
    }

    /// Reserve `airtime` at `now`. On refusal returns the duration after
    /// which a retry can succeed (when the oldest accounted transmission
    /// leaves the window); the reservation is not recorded.
    pub fn try_reserve(&mut self, airtime: Duration, now: Duration) -> Result<(), Duration> {
        if airtime > self.allowance() {
            // Larger than the whole allowance: no amount of waiting helps.
            // Report a full window so callers back off maximally.
            return Err(self.window);
        }
        if self.available(now) >= airtime {
            self.spent.push_back((now, airtime));
            return Ok(());
        }
        let oldest = self.spent.front().map(|&(at, _)| at).unwrap_or(now); // Unreachable: refusal implies accounted spend.
        Err((oldest + self.window).saturating_sub(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn p(sf: u8, bw: u32, cr: u8) -> ModemParams {
        ModemParams {
            bandwidth_hz: bw,
            spreading_factor: sf,
            coding_rate_denominator: cr,
            preamble_symbols: 16,
        }
    }

    /// Known-answer values computed independently from the SX1276 formula.
    #[test]
    fn time_on_air_known_answers() {
        // LongFast (SF11, 250 kHz, 4/5), 255 B: DE off, 243 payload symbols.
        assert_eq!(
            time_on_air(&p(11, 250_000, 5), 255),
            Some(Duration::from_micros(2_156_544))
        );
        // LongFast, 50 B.
        assert_eq!(
            time_on_air(&p(11, 250_000, 5), 50),
            Some(Duration::from_micros(641_024))
        );
        // ShortFast (SF7, 250 kHz, 4/5), 100 B.
        assert_eq!(
            time_on_air(&p(7, 250_000, 5), 100),
            Some(Duration::from_micros(91_264))
        );
        // LongSlow (SF12, 125 kHz, 4/8), 255 B: DE on.
        assert_eq!(
            time_on_air(&p(12, 125_000, 8), 255),
            Some(Duration::from_micros(14_295_040))
        );
        // VeryLongSlow (SF12, 62.5 kHz, 4/8), 233 B: DE on.
        assert_eq!(
            time_on_air(&p(12, 62_500, 8), 233),
            Some(Duration::from_micros(26_492_928))
        );
        // ShortTurbo (SF7, 500 kHz, 4/5), 20 B.
        assert_eq!(
            time_on_air(&p(7, 500_000, 5), 20),
            Some(Duration::from_micros(16_192))
        );
    }

    #[test]
    fn time_on_air_rejects_out_of_range() {
        assert!(time_on_air(&p(13, 250_000, 5), 100).is_none());
        assert!(time_on_air(&p(11, 0, 5), 100).is_none());
        assert!(time_on_air(&p(11, 250_000, 9), 100).is_none());
        assert!(time_on_air(&p(11, 250_000, 5), 256).is_none());
    }

    #[test]
    fn low_data_rate_flag_follows_symbol_time() {
        // SF11 @ 125 kHz: Tsym = 16.384 ms ≥ threshold → DE on, which
        // lengthens the payload relative to naive DE-off math.
        let with_de = time_on_air(&p(11, 125_000, 5), 100).unwrap();
        // Same airtime formula with DE forced off would be 2× the SF11
        // @ 250 kHz value (halving BW exactly doubles every symbol).
        let de_off_reference = 2 * time_on_air(&p(11, 250_000, 5), 100).unwrap();
        assert!(with_de > de_off_reference);
    }

    #[test]
    fn budget_accounts_and_refuses() {
        let window = Duration::from_secs(100);
        let mut b = AirtimeBudget::new(10, window); // 10 s allowance
        let t0 = Duration::ZERO;
        assert_eq!(b.try_reserve(Duration::from_secs(6), t0), Ok(()));
        assert_eq!(b.available(t0), Duration::from_secs(4));
        // Second reservation exceeds the remaining allowance: refused, with
        // a retry hint pointing at the oldest spend leaving the window.
        assert_eq!(
            b.try_reserve(Duration::from_secs(6), Duration::from_secs(50)),
            Err(Duration::from_secs(50))
        );
        // Nothing was recorded by the refusal.
        assert_eq!(b.available(Duration::from_secs(50)), Duration::from_secs(4));
    }

    #[test]
    fn budget_window_slides() {
        let window = Duration::from_secs(100);
        let mut b = AirtimeBudget::new(10, window);
        assert_eq!(
            b.try_reserve(Duration::from_secs(10), Duration::ZERO),
            Ok(())
        );
        assert_eq!(
            b.try_reserve(Duration::from_secs(1), Duration::from_secs(10)),
            Err(Duration::from_secs(90))
        );
        // Once the first spend ages out, the allowance is whole again.
        assert_eq!(
            b.try_reserve(Duration::from_secs(10), Duration::from_secs(101)),
            Ok(())
        );
    }

    #[test]
    fn oversized_reservation_never_succeeds() {
        let mut b = AirtimeBudget::new(1, Duration::from_secs(100)); // 1 s
        assert_eq!(
            b.try_reserve(Duration::from_secs(2), Duration::ZERO),
            Err(Duration::from_secs(100))
        );
    }
}
