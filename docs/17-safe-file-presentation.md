# 17: Safe File Presentation

C1 completes generic non-image file presentation over the existing ADR-0015
attachment pipeline. The transport, manifest, chunk encryption, consent,
resumption, quotas, and hard no-mesh-airtime rules are unchanged. This document
is the user promise, security boundary, and qualification contract.

## 1. User promise

Every attachment row treats its authenticated filename and media type as
sender-provided, untrusted hints. Komms never describes a received file as safe,
never opens a completed file automatically, never uploads it for scanning, and
never fetches a remote preview. A local malware engine may inspect an exported
file if the operating system or user has configured one, but Komms does not
promise that such an engine exists or detected every threat.

Completed inbound files always retain caller-selected protected export. A
smaller reviewed set of matching, non-active filename/media-type pairs may also
offer an explicit **Open** action. That action first warns that the file was not
scanned, then materializes exact verified bytes in app-private temporary storage
and hands them to the operating system. Suspicious files remain export-only.

## 2. Shared fail-closed policy

`kult-node` derives one bounded presentation record from the sanitized basename
and lowercase media-type hint:

- `kind` is an inert icon/label category: image, audio, video, document,
  archive, executable, or other;
- `open_policy` is `protected_media`, `external_open`, or `export_only`; and
- warnings are canonically ordered `media_type_mismatch`, `dangerous_type`,
  `unrecognized_type`, and `missing_filename` tokens.

Executable/script/installer and active-document extensions or media types are
classified as executable and export-only. A known extension whose expected
media types do not include the supplied hint is export-only. Unknown types,
unknown or malformed extensions, and missing filenames are export-only. Only a
recognized matching pair enters the explicit external-open path. Existing
bounded canonical JPEG/PNG and WAV paths remain protected media; this policy
does not create a generic decoder.

The comparison is deliberately small and auditable. It is not content sniffing,
malware detection, sandboxing, or proof that the sender labelled bytes honestly.
Filename text is bidirectionally isolated in the three shells and warning meaning
never depends on color alone.

## 3. Interfaces and lifecycle

Rust exposes `classify_attachment_file`; attachment object records include the
same decision. Strict RPC uses `attachment_file_presentation`, the CLI uses
`kult file-presentation MEDIA_TYPE [FILENAME]`, and UniFFI exports
`attachment_file_presentation` plus typed enums and records.

Desktop, Android, and iOS show the sender-provided-name warning, exact progress,
policy cautions, and export action. Open is visible only for a completed inbound
primary object with `external_open` policy and always requires a second explicit
confirmation. Desktop retains protected temporary materializations only for the
unlocked session. Android uses an app-private cache file and a read-only
`FileProvider` grant, cleaning session and startup orphans. iOS uses a
complete-protection temporary export and removes it when the system-viewer sheet
closes or the row disappears. Failure before handoff removes the transient.

Open/export does not change delivery state, create a receipt, enqueue work,
contact a scanner, or alter internet/LAN/mesh/sneakernet behavior. Large-file and
resume behavior remains the independently sealed, verified F3 chunk lifecycle.

## 4. Qualification matrix

For the core, every wrapper, and each shell:

1. Match `report.pdf` with `application/pdf`; verify an inert document row,
   explicit external-open policy, no auto-open, and an unscanned warning before
   handoff.
2. Present `invoice.pdf.exe` as `application/pdf`; verify executable styling,
   mismatch plus dangerous warnings, export-only behavior, and exact export.
3. Exercise HTML, JavaScript, shell, installer, SVG, and executable hints;
   verify none enters protected-media or external-open paths.
4. Exercise unknown type/extension and missing filename cases; verify stable
   fallback naming, warnings, bidi isolation, and export-only behavior.
5. Interrupt and resume a large transfer, restart after verified chunks, and
   inject duplicate/reordered/corrupt chunks; verify exact progress and that no
   presentation action appears before integrity-checked completion.
6. Cancel, reject, lock, background, close, and restart around export/open; verify
   protected temporary plaintext is removed and sealed progress remains honest.
7. Record queues and mesh frames before every presentation action; verify no new
   delivery work and zero bulk mesh airtime.
8. With keyboard-only navigation, screen readers, large text, RTL content, high
   contrast, and reduced motion, verify filename, type, warnings, progress,
   confirmation, Open, and Export remain understandable and operable.

`fixtures/c1-file-presentation-parity.json` pins the cross-language policy.
Rust/FFI, strict RPC, Kotlin/JVM, Swift binding, and desktop tests must agree with
it. Android debug-APK and iOS Simulator builds provide automated compilation
evidence; real Android/iOS file-picker and external-open interaction remains part
of the M5 hands-on qualification gate and must not be reported as completed
stable-release qualification.

## 5. Explicit non-goals

C1 adds no wire field, capability, preview payload, thumbnail, remote service,
scanner dependency, cloud analysis, archive extraction, office/PDF renderer,
generic media codec, executable launch path, or mesh exception. Video editing,
rich document preview, and claims about third-party viewer safety remain out of
scope.
