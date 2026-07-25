---
name: Release visual approval
about: Record the required human review of Android, iOS, macOS, and Linux release previews
title: "Visual approval: vMAJOR.MINOR.PATCH"
labels: release-visual-approval
---

## Candidate

- Tag or commit:
- Reviewer:
- Review date:

## Android emulator

- Device and API:
- Theme(s):
- Evidence (attach current screenshots/recording, or record a live reviewer
  attestation when screen-capture protection redacts the app):
- [ ] Unlock/create is usable
- [ ] Inbox branding and hierarchy match the Komms brand system
- [ ] Conversation bubbles, composer, menus, and Settings are usable
- [ ] Every animated pairing frame is visible and assembles with a second device's camera
- [ ] No clipping, overlap, unreadable contrast, or stale pre-release styling
- [ ] Approved

## iOS simulator

- Device and iOS version:
- Theme(s):
- Evidence (attach current screenshots/recording, or record a live reviewer
  attestation when screen-capture protection redacts the app):
- [ ] Unlock/create is usable
- [ ] Inbox branding and hierarchy match the Komms brand system
- [ ] Conversation, pairing, menus, and Settings are usable
- [ ] Every animated pairing frame is visible and assembles with a second device's camera
- [ ] No clipping, overlap, unreadable contrast, or stale pre-release styling
- [ ] Approved

## macOS local preview

- macOS version and architecture:
- Theme(s):
- Evidence (attach current screenshots/recording, or record a live reviewer
  attestation when screen-capture protection redacts the app):
- [ ] Locked and unlocked layouts are usable
- [ ] Pairing bundle, animated frames, address, and both QR modes render
- [ ] Every animated pairing frame assembles with a second device's camera
- [ ] LAN permission/discovery and DHT configuration state are understandable
- [ ] Conversation and Settings layouts are usable
- [ ] No clipping, overlap, unreadable contrast, or stale pre-release styling
- [ ] Approved

## Linux packaged preview

- Distribution, desktop environment, and architecture:
- Package type (`AppImage`, `deb`, or `rpm`):
- Theme(s):
- Automated launch-smoke run:
- Evidence (attach current screenshots/recording, or record a live reviewer
  attestation when screen-capture protection redacts the app):
- [ ] The packaged app launches and remains running
- [ ] Locked and unlocked layouts are usable
- [ ] Pairing bundle, animated frames, address, and both QR modes render
- [ ] Every animated pairing frame assembles with a second device's camera
- [ ] Conversation and Settings layouts are usable
- [ ] No clipping, overlap, unreadable contrast, or stale pre-release styling
- [ ] Approved

## Decision

- [ ] All four previews were built from the candidate above
- [ ] Any visual findings are fixed or explicitly documented as release blockers
- [ ] I approve this candidate for publication

Notes:
