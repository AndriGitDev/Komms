---
name: Bug or Beta test report
about: Report a defect, confusing first-use step, or hands-on Beta result
labels: bug
---

Do not post security vulnerabilities here. Use SECURITY.md for private reporting.
Remove message content, identities, Connect codes, safety numbers, recovery
material, capabilities, tokens, private network addresses, and personal paths.

**What happened / what should have happened**
Include the step where you got stuck. An incomplete test is useful too.

**Build and devices**
- App version and exact package filename:
- Package SHA-256 and source revision (if known):
- Device models and OS versions on both sides:
- Physical devices, simulator, or mocked/host-only test:
- For source builds only: Rust version (`rustc --version`):

**Network setup**
Same LAN or separate networks? Guest Wi-Fi, cellular, or configured optional
services? State the operating mode and broad setup without private addresses
or capabilities. Do not attach unredacted configuration or logs.

**Steps and timings**
1.
2.
3.

**Observed result**
- Was the contact accepted in Message Requests?
- Connection label:
- Message state: queued / sent / delivered / failed (record exactly):
- Result after lock, restart, or network change, if tested:

Only an authenticated end-to-end receipt is Delivered. A connected peer,
next-hop acceptance, or wake notification is not proof of recipient delivery.

**Redacted evidence (optional)**
Review screenshots and logs before attaching. A local test report does not
qualify other devices, networks, radio hardware, security, or a stable release.
