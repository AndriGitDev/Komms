//! Mailbox resource policy and explicit mailbox-v1 compatibility wire.

/// Resource limits and retention for a durable mailbox-v2 service.
#[derive(Clone, Copy, Debug)]
pub struct MailboxConfig {
    /// Registered-token cap across all clients.
    pub max_tokens: usize,
    /// Registered-token cap owned by one transport client.
    pub max_tokens_per_client: usize,
    /// Queued-envelope cap per token.
    pub max_per_token: usize,
    /// Queued ciphertext-byte cap per token.
    pub max_bytes_per_token: usize,
    /// Queued-envelope cap attributed to one depositing transport client.
    pub max_per_client: usize,
    /// Queued ciphertext-byte cap attributed to one depositing client.
    pub max_bytes_per_client: usize,
    /// Total queued-envelope cap across all tokens.
    pub max_total_items: usize,
    /// Total queued bytes across all tokens.
    pub max_total_bytes: usize,
    /// Maximum relay retention for one deposited envelope.
    pub envelope_ttl_secs: u64,
    /// Registration lifetime without a recipient refresh.
    pub registration_ttl_secs: u64,
    /// Lifetime of one idempotent collection lease.
    pub lease_ttl_secs: u64,
    /// Live collection leases allowed for one client.
    pub max_live_leases_per_client: usize,
    /// Live collection leases allowed to cover one token.
    pub max_live_leases_per_token: usize,
    /// Live collection leases across the complete relay.
    pub max_live_leases: usize,
    /// Fixed-window request budget per transport client and minute.
    pub max_requests_per_client_per_minute: usize,
    /// Fixed-window request budget across the complete relay and minute.
    pub max_requests_per_minute: usize,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            max_tokens: 65_536,
            max_tokens_per_client: 4_096,
            max_per_token: 256,
            max_bytes_per_token: 16 * 1024 * 1024,
            max_per_client: 4_096,
            max_bytes_per_client: 32 * 1024 * 1024,
            max_total_items: 65_536,
            max_total_bytes: 64 * 1024 * 1024,
            envelope_ttl_secs: 30 * 86_400,
            registration_ttl_secs: 60 * 86_400,
            lease_ttl_secs: 120,
            max_live_leases_per_client: 4,
            max_live_leases_per_token: 2,
            max_live_leases: 4_096,
            max_requests_per_client_per_minute: 2_048,
            max_requests_per_minute: 8_192,
        }
    }
}

/// Maximum delivery-token filters accepted in one check-in request.
pub const MAX_MAILBOX_CHECKIN_TOKENS: usize = 4_096;
/// Maximum envelope rows in one explicitly enabled destructive v1 page.
pub const MAX_MAILBOX_CHECKIN_ENVELOPES: usize = 512;

/// Compatibility wire request on `/komms/mailbox/1`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum MailboxRequest {
    /// Register tokens and return one destructive compatibility page.
    Checkin { tokens: Vec<[u8; 32]> },
    /// Deposit one sealed envelope.
    Deposit { envelope: Vec<u8> },
}

/// Compatibility wire response on `/komms/mailbox/1`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum MailboxResponse {
    /// `serving` is false unless the operator explicitly enabled v1.
    Checkin {
        serving: bool,
        envelopes: Vec<Vec<u8>>,
    },
    /// `true` means the durable v2 store committed the deposit.
    Deposit { accepted: bool },
}
