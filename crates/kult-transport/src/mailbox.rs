//! Relay-v2 mailboxes (docs/05-transports.md §2): store-and-forward for
//! offline recipients, served by ordinary nodes — no dedicated
//! infrastructure, anyone can volunteer.
//!
//! A recipient **checks in** with the relays it chose (the ones it lists as
//! [`crate::DeliveryHint::Relay`] hints in its published bundle), handing
//! over its current delivery-token set as "accept mail for these" filters
//! (docs/04-cryptography.md §7) and draining anything queued under them.
//! Senders **deposit** sealed envelopes; a deposit is accepted only for a
//! registered token. The relay sees rotating 32-byte tokens and sealed
//! envelopes — no identities, no plaintext, no conversation graph — and
//! collection deletes, which is only safe because tokens are
//! recipient-scoped (ADR-0007): a check-in can never drain mail addressed
//! to someone else.

use std::collections::HashMap;

/// Resource limits and retention for a node's mailbox service. Relays are
/// volunteer nodes, so every axis is capped; a deposit beyond a cap is
/// refused, which the sender's delivery engine surfaces as a failed send and
/// retries with backoff — honest refusal, never silent loss.
#[derive(Clone, Copy, Debug)]
pub struct MailboxConfig {
    /// Registered-token cap across all clients. Tokens beyond it are not
    /// registered (deposits for them are refused); already-registered tokens
    /// always refresh.
    pub max_tokens: usize,
    /// Queued-envelope cap per token.
    pub max_per_token: usize,
    /// Total queued bytes across all tokens.
    pub max_total_bytes: usize,
    /// Queued envelopes expire after this many seconds — sized for
    /// human-scale latency, like every other retention window in the system.
    pub envelope_ttl_secs: u64,
    /// Registrations expire after this many seconds unless a check-in
    /// refreshes them; expiry drops the token's queue with it.
    pub registration_ttl_secs: u64,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            max_tokens: 65_536,
            max_per_token: 256,
            max_total_bytes: 64 * 1024 * 1024,
            envelope_ttl_secs: 30 * 86_400,
            registration_ttl_secs: 60 * 86_400,
        }
    }
}

/// What a mailbox currently stores: each registered token with the sealed
/// envelope blobs queued under it.
pub type MailboxContents = Vec<([u8; 32], Vec<Vec<u8>>)>;

/// Byte budget per check-in response, kept comfortably under the
/// request-response codec's response cap. A backlog larger than this is
/// drained across successive check-ins.
const CHECKIN_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Wire request on `/komms/mailbox/1`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum MailboxRequest {
    /// Register these tokens as accept-filters (refreshing their TTL) and
    /// drain everything queued under them.
    Checkin { tokens: Vec<[u8; 32]> },
    /// Deposit one sealed envelope; its delivery token must be registered.
    Deposit { envelope: Vec<u8> },
}

/// Wire response on `/komms/mailbox/1`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum MailboxResponse {
    /// `serving` is false when this node runs no mailbox service — an honest
    /// refusal, distinct from "serving but nothing queued".
    Checkin {
        serving: bool,
        envelopes: Vec<Vec<u8>>,
    },
    Deposit {
        accepted: bool,
    },
}

struct QueuedEnvelope {
    expires_at: u64,
    bytes: Vec<u8>,
}

/// The relay-side state: registered token filters and the sealed envelopes
/// queued under them. Pure data structure — the caller supplies the clock,
/// the swarm task supplies the wire.
pub(crate) struct MailboxStore {
    config: MailboxConfig,
    /// token → registration expiry.
    registered: HashMap<[u8; 32], u64>,
    /// token → queued deposits, oldest first.
    queued: HashMap<[u8; 32], Vec<QueuedEnvelope>>,
    total_bytes: usize,
}

impl MailboxStore {
    pub(crate) fn new(config: MailboxConfig) -> Self {
        Self {
            config,
            registered: HashMap::new(),
            queued: HashMap::new(),
            total_bytes: 0,
        }
    }

    /// Register (or refresh) `tokens` and drain their queues, up to the
    /// per-response byte budget — leftovers surface on the next check-in.
    pub(crate) fn checkin(&mut self, tokens: &[[u8; 32]], now: u64) -> Vec<Vec<u8>> {
        self.sweep(now);
        let expiry = now + self.config.registration_ttl_secs;
        let mut out = Vec::new();
        let mut budget = CHECKIN_BATCH_BYTES;
        for token in tokens {
            if let Some(current) = self.registered.get_mut(token) {
                *current = expiry;
            } else if self.registered.len() < self.config.max_tokens {
                self.registered.insert(*token, expiry);
            } else {
                // Token cap reached: best-effort, skip (deposits for this
                // token stay refused until capacity frees up).
                continue;
            }
            let Some(queue) = self.queued.get_mut(token) else {
                continue;
            };
            let take = queue
                .iter()
                .scan(0usize, |used, q| {
                    *used += q.bytes.len();
                    (*used <= budget).then_some(())
                })
                .count();
            for q in queue.drain(..take) {
                budget -= q.bytes.len();
                self.total_bytes -= q.bytes.len();
                out.push(q.bytes);
            }
            if queue.is_empty() {
                self.queued.remove(token);
            }
        }
        out
    }

    /// Queue one sealed envelope under `token`. Returns whether the deposit
    /// was accepted; refusals (unregistered token, caps) are the sender's
    /// signal to retry elsewhere or later.
    pub(crate) fn deposit(&mut self, token: [u8; 32], bytes: Vec<u8>, now: u64) -> bool {
        self.sweep(now);
        if !self.registered.contains_key(&token) {
            return false;
        }
        let queue = self.queued.entry(token).or_default();
        // Multipath and retry duplicates are normal; one copy suffices (the
        // recipient deduplicates by content id anyway).
        if queue.iter().any(|q| q.bytes == bytes) {
            return true;
        }
        if queue.len() >= self.config.max_per_token
            || self.total_bytes + bytes.len() > self.config.max_total_bytes
        {
            return false;
        }
        self.total_bytes += bytes.len();
        queue.push(QueuedEnvelope {
            expires_at: now + self.config.envelope_ttl_secs,
            bytes,
        });
        true
    }

    /// Whether `token` is currently a registered accept-filter. Decides
    /// where a refused deposit may go on a bridging node (ADR-0009): a
    /// registered token's mail belongs to a libp2p collector even when its
    /// queue is momentarily full, so only *unregistered* tokens fall through
    /// to the mesh-transit buffer.
    pub(crate) fn is_registered(&mut self, token: &[u8; 32], now: u64) -> bool {
        self.sweep(now);
        self.registered.contains_key(token)
    }

    /// Everything currently stored, per token — relay-operator transparency,
    /// and how the M3 inspection test verifies the relay holds nothing but
    /// sealed envelopes.
    pub(crate) fn contents(&self) -> MailboxContents {
        self.queued
            .iter()
            .map(|(token, queue)| (*token, queue.iter().map(|q| q.bytes.clone()).collect()))
            .collect()
    }

    fn sweep(&mut self, now: u64) {
        self.registered.retain(|_, expiry| *expiry > now);
        let registered = &self.registered;
        let total = &mut self.total_bytes;
        self.queued.retain(|token, queue| {
            queue.retain(|q| {
                let live = q.expires_at > now && registered.contains_key(token);
                if !live {
                    *total -= q.bytes.len();
                }
                live
            });
            !queue.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn store() -> MailboxStore {
        MailboxStore::new(MailboxConfig {
            max_tokens: 4,
            max_per_token: 2,
            max_total_bytes: 1024,
            envelope_ttl_secs: 100,
            registration_ttl_secs: 1_000,
        })
    }

    #[test]
    fn deposit_requires_registration() {
        let mut s = store();
        assert!(!s.deposit([1; 32], vec![0xAA], NOW));
        assert!(s.checkin(&[[1; 32]], NOW).is_empty());
        assert!(s.deposit([1; 32], vec![0xAA], NOW));
        assert_eq!(s.checkin(&[[1; 32]], NOW + 1), vec![vec![0xAA]]);
        // Collection deletes.
        assert!(s.checkin(&[[1; 32]], NOW + 2).is_empty());
    }

    #[test]
    fn duplicates_stored_once_and_caps_refuse() {
        let mut s = store();
        s.checkin(&[[1; 32]], NOW);
        assert!(s.deposit([1; 32], vec![1], NOW));
        assert!(s.deposit([1; 32], vec![1], NOW), "duplicate is a no-op ok");
        assert!(s.deposit([1; 32], vec![2], NOW));
        assert!(!s.deposit([1; 32], vec![3], NOW), "per-token cap");
        assert_eq!(s.checkin(&[[1; 32]], NOW).len(), 2);

        s.checkin(&[[2; 32]], NOW);
        assert!(!s.deposit([2; 32], vec![0; 2048], NOW), "byte cap");
    }

    #[test]
    fn token_cap_is_best_effort() {
        let mut s = store();
        let tokens: Vec<[u8; 32]> = (0u8..6).map(|i| [i; 32]).collect();
        s.checkin(&tokens, NOW);
        assert!(s.deposit([3; 32], vec![1], NOW), "within cap: registered");
        assert!(!s.deposit([5; 32], vec![1], NOW), "beyond cap: refused");
    }

    #[test]
    fn envelopes_and_registrations_expire() {
        let mut s = store();
        s.checkin(&[[1; 32]], NOW);
        assert!(s.deposit([1; 32], vec![7], NOW));
        // Envelope TTL passes: the deposit is gone, registration remains.
        assert!(s.checkin(&[[1; 32]], NOW + 101).is_empty());
        assert!(s.deposit([1; 32], vec![8], NOW + 101));
        // Registration TTL passes without a refresh: deposits refused again.
        assert!(!s.deposit([1; 32], vec![9], NOW + 1_500));
        assert_eq!(s.total_bytes, 0, "expiry returned every byte");
    }

    #[test]
    fn checkin_batches_by_bytes() {
        let mut s = MailboxStore::new(MailboxConfig {
            max_total_bytes: 32 * 1024 * 1024,
            max_per_token: 16,
            ..MailboxConfig::default()
        });
        s.checkin(&[[1; 32]], NOW);
        for i in 0..3 {
            assert!(s.deposit([1; 32], vec![i; 2 * 1024 * 1024], NOW));
        }
        // 6 MiB queued, 4 MiB budget: two now, one on the next check-in.
        assert_eq!(s.checkin(&[[1; 32]], NOW).len(), 2);
        assert_eq!(s.checkin(&[[1; 32]], NOW).len(), 1);
    }
}
