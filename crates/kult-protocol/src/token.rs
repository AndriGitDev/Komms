//! Delivery tokens (spec §7): rotating, unlinkable mailbox addresses.
//!
//! `token_i = HMAC-SHA-256(K_mailbox, "KK-token-v1" || epoch_i)`, where
//! `K_mailbox` comes from the session ([`kult_crypto::Session::mailbox_key`])
//! and `epoch_i` is the Unix day number. Only the two parties can compute or
//! recognize the sequence; relays see uncorrelatable 32-byte values.
//!
//! First contact has no session yet, so handshake envelopes use an
//! *introduction token* derived from the recipient's public identity key —
//! computable by anyone (that is what makes contact requests possible) and
//! rate-limited by the contact-gating layer (docs/06-identity-trust.md §7).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_DOMAIN: &[u8] = b"KK-token-v1";
const INTRO_DOMAIN: &[u8] = b"KK-intro-v1";

/// The per-pair mailbox secret (wrap of `Session::mailbox_key()` output).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MailboxKey([u8; 32]);

impl MailboxKey {
    /// Wrap the 32-byte mailbox secret obtained from the session.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Unix day number for token rotation (spec §7: daily epochs).
pub fn epoch_day(now_secs: u64) -> u64 {
    now_secs / 86_400
}

/// The delivery token for a given epoch.
pub fn delivery_token(key: &MailboxKey, epoch: u64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(TOKEN_DOMAIN);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}

/// The introduction token for first-contact envelopes: derived from the
/// recipient's Ed25519 identity key and the epoch. Public by design.
pub fn intro_token(recipient_ed: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(recipient_ed).expect("HMAC accepts any key length");
    mac.update(INTRO_DOMAIN);
    mac.update(&epoch.to_le_bytes());
    mac.finalize().into_bytes().into()
}
