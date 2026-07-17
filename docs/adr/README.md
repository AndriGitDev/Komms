# Architecture Decision Records

ADRs record decisions that constrain Komms across implementations. An accepted
ADR is normative until another ADR explicitly supersedes it. A proposed ADR is
design work under review: it may guide experiments, but it is not a shipped
product promise merely because the file exists.

| ADR | Status | Decision area |
|---|---|---|
| [0001](0001-rust-core.md) | Accepted | Rust core and crate boundaries |
| [0002](0002-xchacha20poly1305.md) | Accepted | XChaCha20-Poly1305 for AEAD |
| [0003](0003-double-ratchet-pqxdh.md) | Accepted | Double Ratchet with hybrid PQXDH |
| [0004](0004-libp2p.md) | Accepted | libp2p internet transport |
| [0005](0005-meshtastic-first.md) | Accepted | Meshtastic-first off-grid transport |
| [0006](0006-agplv3.md) | Accepted | AGPLv3 licensing |
| [0007](0007-recipient-scoped-delivery-tokens.md) | Accepted | Recipient-scoped delivery tokens |
| [0008](0008-in-tree-mdns.md) | Accepted | In-tree hardened mDNS |
| [0009](0009-token-blind-bridging.md) | Accepted | Token-blind internet↔mesh bridging |
| [0010](0010-ffi-embedded-runtime.md) | Accepted | UniFFI embedded runtime |
| [0011](0011-mnemonic-sealed-backup.md) | Accepted | Mnemonic-sealed backup |
| [0012](0012-sender-key-groups.md) | Accepted | Sender-key group messaging |
| [0013](0013-real-time-calls.md) | Proposed | Real-time call transport and gating |
| [0014](0014-versioned-message-content.md) | Accepted | Versioned encrypted message content |
| [0015](0015-encrypted-attachment-pipeline.md) | Proposed; implementation exists | Encrypted attachment pipeline and no-airtime policy |
| [0016](0016-group-mention-content.md) | Accepted | Canonical group-mention content |
| [0017](0017-optional-hybrid-modes.md) | Proposed | Optional service modes and trust boundary |
| [0018](0018-pairwise-rendezvous.md) | Proposed | Rotating pairwise rendezvous |
| [0019](0019-native-wake-gateway.md) | Proposed | Capability-gated native wake |
| [0020](0020-authenticated-message-edits.md) | Accepted | Immutable authenticated message-edit events and deterministic convergence |
| [0021](0021-ephemeral-retention.md) | Accepted | Authenticated local expiry, view-once consumption, and coarse relay retention |
| [0022](0022-convergent-group-polls.md) | Accepted | Visible-vote group polls, fixed electorates, deterministic vote heads, and creator closure |
| [0023](0023-group-roles-and-owner-authority.md) | Accepted | Owner-serialized roles, signed generation-bound admin requests, and authority transfer |

The attachment implementation follows ADR-0015 and its hard no-airtime rule,
but the ADR file still carries Proposed status. This index reports that
governance state rather than silently treating implementation as acceptance.

Use [the template](template.md) for a new decision. Protocol, cryptographic,
transport, replicated-state, or persisted-format changes require an ADR before
implementation; ordinary local UI work does not.

Return to [Start Here](../00-start-here.md), the
[Architecture](../03-architecture.md), or the
[Feature Delivery Plan](../12-feature-delivery-plan.md).
