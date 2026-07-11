# ADR-0005 — Meshtastic as the first off-grid transport

- **Status**: Accepted
- **Date**: 2026-07-11

## Context

Off-grid operation is a founding requirement, not a feature. Options range from custom
LoRa firmware to phone-radio meshes (Bluetooth) to commercial satellite.

## Decision

Integrate with **stock-firmware Meshtastic devices** as a client over BLE/USB-serial,
carrying sealed envelopes on a private application port. No custom firmware in scope.

## Alternatives considered

- **Custom LoRa firmware**: full control of framing/airtime, but forks us away from a
  huge existing device fleet and community, and makes "buy any supported €30 board and
  go" impossible.
- **BLE/Wi-Fi phone-to-phone mesh only (Briar model)**: zero extra hardware but ~10–100 m
  range; kept as a *proximity* transport, insufficient as the off-grid backbone.
- **Satellite (Iridium SBD etc.)**: real coverage, but per-message cost, identity-linked
  subscriptions, and a centralized operator — antithetical to the threat model.

## Consequences

Instant compatibility with an existing global mesh-hardware ecosystem; users can join
with commodity hardware; Meshtastic's store-and-forward and multi-hop routing come free.
Constraints accepted and designed for: ~200-byte frames (fragmentation, 192 B padding
bucket), duty-cycle limits (priority classes, airtime accounting), and Meshtastic's own
crypto treated as an untrusted outer layer. Radio-layer observability is documented
honestly in the threat model.
