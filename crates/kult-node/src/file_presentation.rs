//! Bounded, local-only presentation policy for authenticated attachment hints.
//!
//! Filenames and media types are authenticated sender claims, not proof of a
//! file's contents. This module deliberately performs no content execution,
//! remote lookup, malware scan, or format decode. It only gives every local
//! front door the same conservative presentation and explicit-open policy.

/// Render category for a completed attachment primary object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentFileKind {
    /// A still-image hint. Only the separately bounded JPEG/PNG render path may
    /// display bytes inline.
    Image,
    /// An audio hint. Only the separately bounded canonical WAV path may play
    /// bytes inline.
    Audio,
    /// A video hint, handed to an external application only after user action.
    Video,
    /// A document or bounded textual-data hint.
    Document,
    /// An archive hint.
    Archive,
    /// An executable, script, active-document, installer, or package hint.
    Executable,
    /// An unrecognized or generic binary hint.
    Other,
}

/// Local action policy derived from two untrusted authenticated hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentOpenPolicy {
    /// Existing bounded protected media rendering may be offered explicitly.
    ProtectedMedia,
    /// A completed object may be materialized and handed to the operating
    /// system only after an explicit user action.
    ExternalOpen,
    /// Do not hand the object to an application; caller-selected export is the
    /// only presentation action.
    ExportOnly,
}

/// Stable warning attached to an untrusted file presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttachmentFileWarning {
    /// The filename extension and claimed media type disagree.
    MediaTypeMismatch,
    /// Either hint identifies executable, scripted, or otherwise active data.
    DangerousType,
    /// The media type or extension is outside the reviewed presentation set.
    UnrecognizedType,
    /// No filename was supplied, so extension agreement cannot be checked.
    MissingFilename,
}

/// Render-safe local presentation decision for one attachment primary object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentFilePresentation {
    /// Broad category used for an inert icon and human-readable label.
    pub kind: AttachmentFileKind,
    /// Strongest local action the shells may offer.
    pub open_policy: AttachmentOpenPolicy,
    /// Canonically ordered warnings. These never claim malware detection.
    pub warnings: Vec<AttachmentFileWarning>,
}

/// Classify authenticated but untrusted filename and media-type hints.
///
/// The result never marks content safe. A recognized, matching hint merely
/// permits an explicit operating-system handoff after the object is complete.
pub fn classify_attachment_file(
    media_type: &str,
    filename: Option<&str>,
) -> AttachmentFilePresentation {
    let media_type = media_type.to_ascii_lowercase();
    let extension = filename.and_then(extension);
    let dangerous = dangerous_media_type(&media_type) || extension.is_some_and(dangerous_extension);
    let kind = if dangerous {
        AttachmentFileKind::Executable
    } else {
        media_kind(&media_type)
    };
    let mismatch = extension
        .and_then(expected_media_types)
        .is_some_and(|expected| !expected.contains(&media_type.as_str()));
    let recognized = kind != AttachmentFileKind::Other
        && extension.is_some_and(|value| expected_media_types(value).is_some());

    let mut warnings = Vec::with_capacity(2);
    if mismatch {
        warnings.push(AttachmentFileWarning::MediaTypeMismatch);
    }
    if dangerous {
        warnings.push(AttachmentFileWarning::DangerousType);
    }
    if !recognized {
        warnings.push(AttachmentFileWarning::UnrecognizedType);
    }
    if filename.is_none() {
        warnings.push(AttachmentFileWarning::MissingFilename);
    }
    warnings.sort_unstable();
    warnings.dedup();

    let open_policy = if dangerous || mismatch || !recognized || filename.is_none() {
        AttachmentOpenPolicy::ExportOnly
    } else if matches!(
        media_type.as_str(),
        "image/jpeg" | "image/png" | "audio/wav"
    ) {
        AttachmentOpenPolicy::ProtectedMedia
    } else {
        AttachmentOpenPolicy::ExternalOpen
    };

    AttachmentFilePresentation {
        kind,
        open_policy,
        warnings,
    }
}

fn extension(filename: &str) -> Option<&str> {
    let (_, value) = filename.rsplit_once('.')?;
    (!value.is_empty()
        && value.len() <= 16
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(value)
}

fn media_kind(media_type: &str) -> AttachmentFileKind {
    if dangerous_media_type(media_type) {
        return AttachmentFileKind::Executable;
    }
    if media_type.starts_with("image/") {
        AttachmentFileKind::Image
    } else if media_type.starts_with("audio/") {
        AttachmentFileKind::Audio
    } else if media_type.starts_with("video/") {
        AttachmentFileKind::Video
    } else if matches!(
        media_type,
        "application/pdf"
            | "application/json"
            | "application/rtf"
            | "application/vnd.oasis.opendocument.text"
            | "application/vnd.oasis.opendocument.spreadsheet"
            | "application/vnd.oasis.opendocument.presentation"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "text/csv"
            | "text/markdown"
            | "text/plain"
    ) {
        AttachmentFileKind::Document
    } else if matches!(
        media_type,
        "application/gzip"
            | "application/zip"
            | "application/x-7z-compressed"
            | "application/x-tar"
            | "application/x-zip-compressed"
    ) {
        AttachmentFileKind::Archive
    } else {
        AttachmentFileKind::Other
    }
}

fn dangerous_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/java-archive"
            | "application/javascript"
            | "application/vnd.android.package-archive"
            | "application/x-apple-diskimage"
            | "application/x-deb"
            | "application/x-dosexec"
            | "application/x-executable"
            | "application/x-msdownload"
            | "application/x-msi"
            | "application/x-rpm"
            | "application/x-sh"
            | "image/svg+xml"
            | "text/html"
            | "text/javascript"
            | "text/x-shellscript"
    )
}

fn dangerous_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "apk"
            | "app"
            | "bat"
            | "cmd"
            | "com"
            | "deb"
            | "desktop"
            | "dmg"
            | "dll"
            | "exe"
            | "hta"
            | "htm"
            | "html"
            | "iso"
            | "jar"
            | "js"
            | "lnk"
            | "mjs"
            | "msi"
            | "pkg"
            | "ps1"
            | "reg"
            | "rpm"
            | "scr"
            | "sh"
            | "svg"
            | "vbs"
            | "zsh"
    )
}

fn expected_media_types(extension: &str) -> Option<&'static [&'static str]> {
    Some(match extension.to_ascii_lowercase().as_str() {
        "txt" => &["text/plain"],
        "md" => &["text/markdown", "text/plain"],
        "csv" => &["text/csv", "text/plain"],
        "json" => &["application/json", "text/plain"],
        "pdf" => &["application/pdf"],
        "rtf" => &["application/rtf", "text/rtf"],
        "odt" => &["application/vnd.oasis.opendocument.text"],
        "ods" => &["application/vnd.oasis.opendocument.spreadsheet"],
        "odp" => &["application/vnd.oasis.opendocument.presentation"],
        "docx" => &["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
        "xlsx" => &["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
        "pptx" => &["application/vnd.openxmlformats-officedocument.presentationml.presentation"],
        "zip" => &["application/zip", "application/x-zip-compressed"],
        "tar" => &["application/x-tar"],
        "gz" => &["application/gzip"],
        "7z" => &["application/x-7z-compressed"],
        "jpg" | "jpeg" => &["image/jpeg"],
        "png" => &["image/png"],
        "gif" => &["image/gif"],
        "webp" => &["image/webp"],
        "wav" => &["audio/wav"],
        "mp3" => &["audio/mpeg"],
        "ogg" => &["audio/ogg", "application/ogg"],
        "m4a" => &["audio/mp4"],
        "mp4" => &["video/mp4"],
        "webm" => &["video/webm"],
        "mov" => &["video/quicktime"],
        "bin" => &["application/octet-stream"],
        "apk" => &["application/vnd.android.package-archive"],
        "dmg" => &["application/x-apple-diskimage"],
        "deb" => &["application/x-deb"],
        "exe" | "dll" | "com" | "scr" => &[
            "application/x-dosexec",
            "application/x-executable",
            "application/x-msdownload",
        ],
        "msi" => &["application/x-msi", "application/x-msdownload"],
        "jar" => &["application/java-archive"],
        "js" | "mjs" => &["application/javascript", "text/javascript"],
        "sh" | "zsh" => &["application/x-sh", "text/x-shellscript"],
        "htm" | "html" => &["text/html"],
        "svg" => &["image/svg+xml"],
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_token(value: AttachmentFileKind) -> &'static str {
        match value {
            AttachmentFileKind::Image => "image",
            AttachmentFileKind::Audio => "audio",
            AttachmentFileKind::Video => "video",
            AttachmentFileKind::Document => "document",
            AttachmentFileKind::Archive => "archive",
            AttachmentFileKind::Executable => "executable",
            AttachmentFileKind::Other => "other",
        }
    }

    fn policy_token(value: AttachmentOpenPolicy) -> &'static str {
        match value {
            AttachmentOpenPolicy::ProtectedMedia => "protected_media",
            AttachmentOpenPolicy::ExternalOpen => "external_open",
            AttachmentOpenPolicy::ExportOnly => "export_only",
        }
    }

    fn warning_token(value: AttachmentFileWarning) -> &'static str {
        match value {
            AttachmentFileWarning::MediaTypeMismatch => "media_type_mismatch",
            AttachmentFileWarning::DangerousType => "dangerous_type",
            AttachmentFileWarning::UnrecognizedType => "unrecognized_type",
            AttachmentFileWarning::MissingFilename => "missing_filename",
        }
    }

    #[test]
    fn matching_known_files_get_only_explicit_reviewed_actions() {
        let pdf = classify_attachment_file("application/pdf", Some("report.pdf"));
        assert_eq!(pdf.kind, AttachmentFileKind::Document);
        assert_eq!(pdf.open_policy, AttachmentOpenPolicy::ExternalOpen);
        assert!(pdf.warnings.is_empty());

        let png = classify_attachment_file("image/png", Some("photo.png"));
        assert_eq!(png.open_policy, AttachmentOpenPolicy::ProtectedMedia);
        assert!(png.warnings.is_empty());
    }

    #[test]
    fn mismatch_executable_unknown_and_missing_names_fail_closed() {
        let disguised = classify_attachment_file("application/pdf", Some("invoice.pdf.exe"));
        assert_eq!(disguised.kind, AttachmentFileKind::Executable);
        assert_eq!(disguised.open_policy, AttachmentOpenPolicy::ExportOnly);
        assert!(disguised
            .warnings
            .contains(&AttachmentFileWarning::MediaTypeMismatch));
        assert!(disguised
            .warnings
            .contains(&AttachmentFileWarning::DangerousType));

        let unknown = classify_attachment_file("application/octet-stream", Some("payload.bin"));
        assert_eq!(unknown.kind, AttachmentFileKind::Other);
        assert_eq!(unknown.open_policy, AttachmentOpenPolicy::ExportOnly);
        assert!(unknown
            .warnings
            .contains(&AttachmentFileWarning::UnrecognizedType));

        let nameless = classify_attachment_file("application/pdf", None);
        assert_eq!(nameless.open_policy, AttachmentOpenPolicy::ExportOnly);
        assert!(nameless
            .warnings
            .contains(&AttachmentFileWarning::MissingFilename));
    }

    #[test]
    fn active_documents_never_enter_inline_or_external_open_paths() {
        for (media_type, filename) in [
            ("text/html", "page.html"),
            ("image/svg+xml", "drawing.svg"),
            ("application/javascript", "tool.js"),
            ("application/vnd.android.package-archive", "update.apk"),
        ] {
            let result = classify_attachment_file(media_type, Some(filename));
            assert_eq!(result.kind, AttachmentFileKind::Executable);
            assert_eq!(result.open_policy, AttachmentOpenPolicy::ExportOnly);
            assert!(result
                .warnings
                .contains(&AttachmentFileWarning::DangerousType));
        }
    }

    #[test]
    fn shared_c1_fixture_matches_the_rust_authority() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/c1-file-presentation-parity.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let filename = case["filename"].as_str();
            let result = classify_attachment_file(case["media_type"].as_str().unwrap(), filename);
            assert_eq!(kind_token(result.kind), case["kind"].as_str().unwrap());
            assert_eq!(
                policy_token(result.open_policy),
                case["open_policy"].as_str().unwrap()
            );
            let warnings = result
                .warnings
                .into_iter()
                .map(warning_token)
                .collect::<Vec<_>>();
            assert_eq!(
                warnings,
                case["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }
}
