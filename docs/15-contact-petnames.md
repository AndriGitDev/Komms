# 15: Private Contact Names

B5 ships contact rename as an endpoint-only petname feature across `kult-node`,
strict RPC/CLI, UniFFI, desktop, Android, and iOS. This document is the user
promise, security boundary, and qualification contract.

## 1. Identity and privacy contract

A Komms identity is a cryptographic peer key. A petname is only the private human
label one local user assigns to that key. Rename always takes the exact peer key;
no API searches for or targets a contact by display text.

The mutation rewrites only the sealed contact record and emits one local
`ContactRenamed` event. It creates no DHT lookup, capability change, message,
envelope, sender-key or ratchet work, mailbox request, notification, analytics,
queue entry, or internet/LAN/mesh/sneakernet transport work. The petname survives
restart and is included in the current `KKR5` contact backup. It is not synced
to peers or linked devices by any other path.

## 2. Name contract

The shared core owns validation and assessment for every interface:

- normalize to Unicode NFC before comparison or storage;
- accept at most 256 UTF-8 bytes after normalization;
- reject empty, all-whitespace, or control-bearing names;
- permit exact duplicate names because the peer key remains authoritative;
- exclude the contact being renamed from its own duplicate count;
- return whether normalization changed the submitted text.

Assessment returns stable warning codes in this order when applicable:

| Code | Meaning |
|---|---|
| `duplicate_name` | One or more other local contacts use the same normalized petname. |
| `confusable_name` | The text mixes selected Latin/Greek/Cyrillic lookalikes or resembles another local petname under the conservative shared skeleton. |
| `bidirectional_control` | Directional formatting characters can change visual order. |
| `invisible_character` | Invisible formatting characters can hide distinctions. |

The confusable check is intentionally conservative, not a claim of complete
Unicode UTS #39 coverage. A warning does not reject a name permanently. It blocks
the mutation until the caller presents the returned risks and explicitly retries
with warning acceptance. Interfaces must retain peer-key-derived or other stable
context wherever duplicate names could otherwise be ambiguous.

## 3. Shipped interfaces

Strict daemon operations are `contact_name_assessment` and `rename_contact`.
Unknown fields are rejected. The CLI equivalents are:

```text
kult contact-name-check PEER_HEX NAME...
kult contact-rename PEER_HEX NAME...
kult contact-rename PEER_HEX --accept-warnings NAME...
```

UniFFI exposes the same assessment record, warning enum, mutation, and local
event. Desktop offers Rename in the active contact header; Android offers a
TalkBack-accessible Rename row action; iOS offers swipe and context-menu actions.
Each shell uses its B15 incognito text control, explains that the label stays
private and local, assesses before mutation, renders every warning without
color-only meaning, and requires explicit confirmation for a warned name.

## 4. Qualification matrix

For each front door and shell:

1. Rename a contact from decomposed `e` + combining acute and verify the stored
   and displayed form is NFC `é` after restart.
2. Create another contact with the proposed name. Verify assessment reports the
   exact duplicate count, the first rename is blocked, explicit acceptance
   succeeds, and both peer keys remain separately actionable.
3. Try a mixed-script lookalike, bidirectional control, and invisible formatting
   character. Verify each applicable warning is readable and cancellation makes
   no mutation.
4. Verify empty, whitespace-only, control-bearing, and over-limit names fail
   without changing the current record.
5. Record queue and transport state before rename. Verify they are unchanged and
   only the local rename event appears.
6. Restart and restore through `KKR5`; verify the exact normalized petname remains
   attached to the same peer key.
7. With assistive technology and large text enabled, verify the Rename action,
   private-local explanation, warning list, confirmation, error state, and
   duplicate-contact disambiguation remain usable.

The deterministic cross-language fixture is
`fixtures/b5-contact-rename-parity.json`. Rust core, RPC, UniFFI, Kotlin, Swift,
and desktop acceptance tests must agree with it.

## 5. Deferred work

Komms does not ship global usernames or self-advertised display names. A future
signed self-display suggestion would be non-unique, could never silently replace
a recipient's local petname, and would alter the prekey-bundle/DHT compatibility
surface. It therefore requires a separate ADR, versioning and downgrade rules,
old-client behavior, bounded decoding, privacy review, and cross-version tests.
