# 44: Contributor Path

This is the shortest supported route from a clean checkout to a focused Komms
change. It does not grant release authority and does not require signing keys,
store accounts, service credentials, production infrastructure, every platform
SDK, or the complete publication matrix.

## 1. Choose one bounded target

List the checked-in profiles:

```sh
python3 scripts/contributor-check.py --list
```

Then dry-run one profile to see its exact commands and owned paths:

```sh
python3 scripts/contributor-check.py --dry-run protocol
```

The available profiles are:

| Profile | Use it for |
|---|---|
| `protocol` | bounded cryptographic and wire-code changes |
| `storage-node` | ordinary store, node, and transport behavior |
| `desktop` | the desktop backend and shell |
| `android-core` | generated Kotlin bindings and JVM behavior without an Android SDK |
| `ios-core` | generated Swift bindings and host behavior without Xcode |
| `localization` | catalogs, generated shell resources, source coverage, plurals, bidi safety, and fallback behavior without a platform SDK |
| `documentation` | prose, evidence vocabulary, and consent-accessibility copy |
| `stewardship` | operator, licensing, funding, privacy, legal-process, incident, and public-evidence records without deployment or credentials |

Run the selected profile before opening a pull request:

```sh
python3 scripts/contributor-check.py PROFILE
```

The profile runner removes signing/provider credential variables from child
processes and rejects history-changing, publishing, registry-changing, and
remote-login commands. It never pushes, tags, signs, packages for publication,
uploads, merges, or releases. The source-controlled profile is the reviewable
contract; do not replace it with an opaque local wrapper in an evidence record.

## 2. Pick a reviewable issue

An issue labelled `good first change` must name:

1. one concrete user or maintainer problem;
2. the exact in-scope and out-of-scope paths;
3. observable acceptance criteria;
4. the recommended contributor profile; and
5. whether a sensitive-surface owner must review it.

`help wanted` means the scope is accepted but may require more project context.
`accessibility`, `localization`, `documentation`, `tests`, and the platform
labels describe the kind of work. They do not override `security-sensitive` or
`protocol-compatibility`.

Use the repository's “Good first change” issue form for a new bounded proposal.
Before implementing an existing issue, comment that you intend to work on it so
duplicate effort is visible. Assignment is coordination, not exclusive
ownership.

## 3. Orient by dependency direction

The compact path is:

```text
kult-crypto
  └─> kult-protocol + kult-store
        └─> kult-transport + kult-node
              └─> kult-ffi / kultd
                    └─> desktop / Android / iOS shells
```

The authoritative boundaries are
[Architecture](03-architecture.md) and the
[Implementation Guide](09-implementation-guide.md). Shells present typed core
state; they do not invent protocol, trust, delivery, or storage semantics.
Deterministic cross-layer fixtures live in `fixtures/`. Extend an existing
versioned fixture when the contract already has one; introduce a new fixture
only with a documented owner, bound, compatibility meaning, and consumer test.

## 4. Sensitive review boundaries

The following changes require the recorded owner in `CODEOWNERS`, even when the
diff is small:

- cryptography, protocol codecs, canonical limits, trust, and downgrade rules;
- storage sealing, migrations, backup/recovery, and atomic transitions;
- admission, discovery, mailbox custody, rendezvous, wake, or provider policy;
- FFI/RPC compatibility, release workflows, signing, dependencies, or evidence
  validators;
- security/privacy claims, the threat model, accepted ADRs, governance,
  licensing, incident handling, or publication controls; and
- localization of recovery, safety-number, authority, consent, blocking,
  delivery-state, or security-warning copy.

Do not weaken a bound or error path to make a test pass. A behavior or wire/state
change needs the applicable ADR/spec update before implementation. Suspected
vulnerabilities use the private route in [SECURITY.md](../SECURITY.md), not a
public issue containing exploit or secret material.

## 5. Pull-request handoff

Keep one concern per pull request. The template asks for:

- the problem and intentionally excluded work;
- the contract or issue it implements;
- the selected contributor profile and any narrower focused checks;
- user-visible, compatibility, privacy, and accessibility effects;
- deterministic fixture changes; and
- every unrun or externally blocked check.

An ordinary contribution does not need the full release matrix. A maintainer may
request broader checks when a shared contract changes. Only an explicitly
authorized publication candidate runs the complete
[local release gate](24-local-release-gate.md), and only maintainers publish.

## 6. Troubleshooting

| Symptom | Resolution |
|---|---|
| `missing prerequisite` | Install only the prerequisite named by the selected profile and its platform README. Do not install a release credential. |
| Cargo cannot resolve dependencies | Run the same profile once with normal network access. The committed lockfiles remain authoritative. |
| Android asks for an SDK | Use `android-core`; it forces `-Pkomms.androidApp=false`. The application profile is a separate platform task. |
| Swift host linking fails | Run `apps/ios/scripts/test-core.sh` from the repository root; it builds the host FFI library before Swift tests. |
| Desktop system library is missing | Install the packages listed in `apps/desktop/README.md`; no packaging/signing setup is needed. |
| A localization output is stale | Edit the canonical catalogs, run `python3 scripts/localization.py generate`, and rerun the `localization` profile. Do not edit generated platform resources directly. |
| An accessibility contract check fails | Read [Localization and Accessibility](45-localization-accessibility.md), fix the affected semantic or presentation boundary, and retain physical/external rows as open unless they were genuinely run. |
| A fixture changed unexpectedly | Stop and identify the normative owner. Do not regenerate compatibility data merely to accept a new output. |
| The focused profile passes but another area fails | Report the exact extra command and failure. Do not claim the unrelated target passed. |
| The proposed change crosses a sensitive boundary | Narrow it, or open a design issue and wait for the recorded owner before implementation. |

Ask in the issue when the failure remains ambiguous. Include OS, architecture,
toolchain version, selected profile, exact failing command, and redacted output;
never include credentials, keys, recovery material, contact data, or message
content.
