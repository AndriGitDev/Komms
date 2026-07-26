# ADR-0026: Offline account authority and quorum-authorized devices

- **Status**: Proposed
- **Date**: 2026-07-26
- **Supersedes on acceptance**: the device-authority and recovery rules in
  [ADR-0024](0024-account-authorized-linked-devices.md); its per-device
  ratchet, delivery, group-chain, and convergent-sync boundaries remain.

## Context

ADR-0024 gives every linked device the stable account private key. That makes
offline linking simple, but it also makes permanent revocation impossible: a
lost device retains the authority needed to issue a new device certificate and
sign a higher-generation manifest after its old certificate is revoked.

The stable account address must survive ordinary device changes. Each physical
device must still have independent ratchets and sender chains, and linking must
remain possible without a project account service. At the same time, a
single compromised secondary device must not be able to add a replacement
credential, remove honest devices, or override a later recovery.

This is a pre-stable alpha protocol. Preserving an insecure authority layout
for silent compatibility is less important than establishing a recoverable
model before people rely on it.

## Decision

### 1. The account root is an offline recovery authority

The stable account Ed25519 key remains the address and trust anchor. Its private
key signs the genesis device manifest and is then removed from the live Komms
store. It is represented only by the user's encrypted recovery material and
may be opened transiently for an explicit recovery operation.

No device-link package, backup intended for routine device migration, sync
event, or online device state contains the account private key. Platform secure
storage may protect device keys, but an exportable copy of the account root is
not retained as a convenience credential.

Ordinary messages and state changes are signed or authenticated by independent
device keys. A device certificate and the accepted manifest chain bind those
keys to the stable account. Verifiers never require an online account-root
signature for ordinary messaging.

### 2. Manifest transitions are authorized by the previous active set

The manifest becomes an append-only transition chain. Every transition commits
to:

- the account public key;
- the exact parent manifest hash and generation;
- the complete next active/revoked device set;
- any newly introduced immutable device certificates;
- a transition kind and random transition id; and
- signatures from a strict majority of the parent's active devices.

A sole active device can link a second device. Once two or more devices are
active, no single device can add, revoke, rename, or replace credentials.
Losing enough devices to satisfy the majority requires account-root recovery;
availability is not purchased by giving every device unilateral account
authority.

Concurrent valid transitions from one parent are forks, not mergeable sets.
Clients retain the first accepted branch, surface a safety event for a
conflicting branch, and require account-root recovery to converge them.
Lexicographic state-id ordering must not silently choose account authority.

### 3. Recovery is a root-authorized epoch change

An explicit recovery opens the account root, names the last manifest known to
the recovering user, and signs a recovery transition with a monotonically
stored recovery epoch and a random recovery id. The transition:

- revokes every previously active device;
- introduces exactly one fresh recovery device;
- rotates sync, rendezvous, wake, group-sender, and per-device delivery state;
  and
- makes device-quorum transitions descending from an older recovery epoch
  invalid, regardless of their numeric manifest generation.

Clients persist the greatest accepted recovery epoch and its transition hash.
A conflicting root-signed transition at the same epoch is a visible recovery
conflict and requires safety-number re-verification; it is never resolved
silently. Old root transitions, device-only descendants of an old epoch, and
attempted un-revocation fail closed.

The account root remains the ultimate takeover secret. Recovery UI therefore
states that anyone with the recovery material controls the account, and rate
limits mnemonic attempts without sending recovery material to a service.

### 4. Linking remains an ordinary-user ceremony

The visible flow remains scan, compare, and confirm. Underneath it:

1. the candidate creates an independent device key;
2. the active devices sign one canonical proposed transition;
3. the candidate activates only after the strict-majority proof and manifest
   chain verify; and
4. selected history is transferred over the existing transcript-bound sealed
   channel.

The UI asks for additional active-device approval only when the threshold
requires it. Recovery words are required when too many devices are unavailable.
The network has no account server and no operator can approve a device.

### 5. Alpha migration fails honestly

An account that never exported its root to another device may migrate in place:
it issues a genesis device transition, exports recovery material, verifies that
the live database no longer contains the root, and retains its address.

An ADR-0024 account that distributed the root to another device cannot prove
that every copy was erased. It must perform an explicit authority reset. Before
stable wire v1, the safe default is a new account identity with guided contact
re-verification. A compatibility tool may preserve local history and petnames,
but it must not label the old safety number or device revocations as preserved.

No automatic migration claims to repair an already copied root.

## Alternatives considered

### Keep the account root on every device and remember revoked ids

Rejected. A revoked holder can mint a new id that does not appear in the
revocation set and sign the next manifest.

### Designate one permanently privileged online owner device

Rejected. It converts theft or compromise of that device into silent account
takeover and makes loss of that device a special availability failure.

### Require the offline root for every link or revocation

Rejected. It is cryptographically simple but makes normal multi-device use
unnecessarily hostile. Majority transitions handle routine changes; the root
handles loss and conflict.

### Let deterministic ordering choose between authority forks

Rejected. Deterministic convergence is suitable for ordinary replicated data,
not for choosing which attacker-controlled device set owns an identity.

## Consequences

- Linked devices no longer receive the one secret that can recreate account
  authority after revocation.
- Normal linking remains service-independent and usually needs only the
  devices already in the user's hands.
- Losing half or more of the active devices requires recovery material. This
  is an intentional safety boundary and must be rehearsed in onboarding.
- Manifests carry a bounded proof chain or checkpoint from the last state a
  contact accepted; codecs and storage need explicit versioning and limits.
- Existing multi-device alpha identities require a visible authority reset and
  possibly a new safety number.
- Acceptance requires stolen-device, offline-majority, fork, replay, old
  backup, and recovery-conflict tests before ADR-0024's permanent-revocation
  claim can return.
