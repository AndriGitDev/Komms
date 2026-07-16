//! The desktop shell's view of a running node: a thin, testable layer over
//! `kult-ffi`'s [`KultNode`] that speaks the webview's language (serde JSON
//! view-models, string errors) and nothing else.
//!
//! Everything the UI can do goes through [`Session`] — the Tauri commands
//! in [`crate::commands`] are one-line wrappers. That keeps the whole
//! behavior testable without a webview: the integration test drives two
//! [`Session`]s through exactly these methods.
//!
//! The shell adds **no** protocol logic. Honesty rules from the core carry
//! through verbatim: delivery states come from the node (`delivered` means
//! an end-to-end encrypted receipt), errors are the node's own words, and
//! the backup mnemonic is returned exactly once and never stored.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use image::codecs::jpeg::JpegEncoder;
use image::{ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};

use kult_ffi::{
    canonicalize_recorded_audio, default_config, edit_image, probe_edited_image,
    probe_recorded_audio, Attachment, AttachmentConversation, AttachmentDirection,
    AttachmentFileKind as FfiAttachmentFileKind,
    AttachmentFilePresentation as FfiAttachmentFilePresentation,
    AttachmentFileWarning as FfiAttachmentFileWarning,
    AttachmentOpenPolicy as FfiAttachmentOpenPolicy, AttachmentState, AudioInfo, CarrierCapability,
    Config, ContactNameAssessment as FfiContactNameAssessment,
    ContactNameWarning as FfiContactNameWarning, ContentKind, CustomIcon as FfiCustomIcon,
    CustomIconCrop as FfiCustomIconCrop, CustomIconTarget as FfiCustomIconTarget,
    CustomIconTargetKind as FfiCustomIconTargetKind, DeliveryState, Direction, Event,
    EventListener, Folder as FfiFolder, FolderConversation as FfiFolderConversation,
    FolderConversationResult as FfiFolderConversationResult, FolderSelection as FfiFolderSelection,
    FolderSelectionKind as FfiFolderSelectionKind, FolderTarget as FfiFolderTarget,
    FolderTargetKind as FfiFolderTargetKind, GroupPoll as FfiGroupPoll, Hint, ImageCrop,
    ImageEditRecipe, ImageEditRegion, ImageEditRegionKind, ImageInfo, KdfChoice, KultNode,
    Label as FfiLabel, LabelConversation as FfiLabelConversation,
    LabelFilterResult as FfiLabelFilterResult, LabelMatchMode as FfiLabelMatchMode,
    LabelTarget as FfiLabelTarget, LabelTargetKind as FfiLabelTargetKind,
    MentionCapabilityIssueReason, MentionSpan, NatVerdict, Pin as FfiPin,
    PinConversation as FfiPinConversation, PinConversationResult as FfiPinConversationResult,
    PinTarget as FfiPinTarget, PinTargetKind as FfiPinTargetKind, ScheduledConversation,
    StaleFolder as FfiStaleFolder, StaleLabel as FfiStaleLabel,
    TextFormatBlockKind as FfiTextFormatBlockKind, TextFormatHighlight as FfiTextFormatHighlight,
    TextFormatStyle as FfiTextFormatStyle, ThemePreference as FfiThemePreference, AUDIO_MAX_BYTES,
    AUDIO_MEDIA_TYPE, IMAGE_MAX_INPUT_BYTES, IMAGE_MEDIA_TYPE,
};

use crate::qr;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PrivateTemp(PathBuf);

impl PrivateTemp {
    fn destination(extension: &str) -> Result<Self, String> {
        for _ in 0..32 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "komms-media-{}-{sequence}.{extension}",
                std::process::id()
            ));
            if !path.exists() {
                return Ok(Self(path));
            }
        }
        Err("could not allocate a private media path".to_owned())
    }

    fn empty(extension: &str) -> Result<Self, String> {
        use std::io::Write;

        for _ in 0..32 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "komms-media-{}-{sequence}.{extension}",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.flush().map_err(|error| error.to_string())?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Err("could not allocate a private media path".to_owned())
    }

    fn with_bytes(extension: &str, bytes: &[u8]) -> Result<Self, String> {
        let temp = Self::empty(extension)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temp.path())
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(temp)
    }

    fn copy_bounded(extension: &str, source: &Path, max_bytes: u64) -> Result<Self, String> {
        let mut input = std::fs::File::open(source).map_err(|error| error.to_string())?;
        let length = input.metadata().map_err(|error| error.to_string())?.len();
        if length == 0 || length > max_bytes {
            return Err(format!(
                "selected file is empty or exceeds {max_bytes} bytes"
            ));
        }
        let temp = Self::empty(extension)?;
        let result = (|| {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(temp.path())
                .map_err(|error| error.to_string())?;
            let copied = std::io::copy(
                &mut Read::by_ref(&mut input).take(max_bytes + 1),
                &mut output,
            )
            .map_err(|error| error.to_string())?;
            if copied != length || copied > max_bytes {
                return Err(
                    "selected file changed or exceeded its size limit while staging".to_owned(),
                );
            }
            output.sync_all().map_err(|error| error.to_string())
        })();
        if let Err(error) = result {
            drop(temp);
            return Err(error);
        }
        Ok(temp)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

const DESKTOP_ATTACHMENT_MAX_BYTES: u64 = 512 * 1024 * 1024;

struct PendingImageEdit {
    original: PrivateTemp,
    final_asset: PrivateTemp,
    info: ImageInfo,
}

/// Integer crop received from the keyboard-operable desktop editor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiImageCrop {
    /// Left edge after orientation normalization.
    pub x: u32,
    /// Top edge after orientation normalization.
    pub y: u32,
    /// Non-zero crop width.
    pub width: u32,
    /// Non-zero crop height.
    pub height: u32,
}

/// One ordered manual blur or pixelation rectangle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiImageRegion {
    /// `blur` or `pixelate`.
    pub kind: String,
    /// Left edge on the rotated final canvas.
    pub x: u32,
    /// Top edge on the rotated final canvas.
    pub y: u32,
    /// Non-zero region width.
    pub width: u32,
    /// Non-zero region height.
    pub height: u32,
    /// Blur radius or pixel block edge.
    pub strength: u32,
}

/// Complete deterministic desktop edit recipe.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiImageEditRecipe {
    /// Optional exact integer crop.
    pub crop: Option<UiImageCrop>,
    /// Clockwise quarter turns.
    pub rotation_quarter_turns: u8,
    /// Ordered manual privacy operations.
    pub regions: Vec<UiImageRegion>,
}

impl UiImageEditRecipe {
    fn into_ffi(self) -> Result<ImageEditRecipe, String> {
        Ok(ImageEditRecipe {
            crop: self.crop.map(|crop| ImageCrop {
                x: crop.x,
                y: crop.y,
                width: crop.width,
                height: crop.height,
            }),
            rotation_quarter_turns: self.rotation_quarter_turns,
            regions: self
                .regions
                .into_iter()
                .map(|region| {
                    Ok(ImageEditRegion {
                        kind: match region.kind.as_str() {
                            "blur" => ImageEditRegionKind::Blur,
                            "pixelate" => ImageEditRegionKind::Pixelate,
                            _ => return Err("image region must be blur or pixelate".to_owned()),
                        },
                        x: region.x,
                        y: region.y,
                        width: region.width,
                        height: region.height,
                        strength: region.strength,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

/// Opaque protected draft plus the exact canonical final review.
#[derive(Clone, Debug, Serialize)]
pub struct UiImageReview {
    /// Opaque session-local draft identifier.
    pub token: String,
    /// Final width.
    pub width: u32,
    /// Final height.
    pub height: u32,
    /// Exact canonical PNG size.
    pub encoded_bytes: u64,
    /// Bounded exact final bytes for the local protected review surface.
    pub data_url: String,
}

impl Drop for PrivateTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn cleanup_media_temps() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("komms-media-"))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn open_with_system(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("rundll32.exe");
        command.arg("url.dll,FileProtocolHandler");
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("external file opening is unavailable on this platform".to_owned());

    command
        .arg(path)
        .spawn()
        .map_err(|error| format!("could not open attachment: {error}"))?;
    Ok(())
}

fn generate_preview(path: &Path, media_type: &str) -> Result<Option<PrivateTemp>, String> {
    if !matches!(media_type, "image/jpeg" | "image/png") {
        return Ok(None);
    }
    let mut reader = ImageReader::open(path)
        .map_err(|error| format!("image preview: {error}"))?
        .with_guessed_format()
        .map_err(|error| format!("image preview: {error}"))?;
    if !matches!(reader.format(), Some(ImageFormat::Jpeg | ImageFormat::Png)) {
        return Err("image preview: selected content is not JPEG or PNG".to_owned());
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(192 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| format!("image preview: {error}"))?;

    for (edge, quality) in [(512, 82), (448, 72), (384, 62), (320, 52)] {
        let thumbnail = image.thumbnail(edge, edge);
        let mut encoded = Vec::new();
        JpegEncoder::new_with_quality(&mut encoded, quality)
            .encode_image(&thumbnail)
            .map_err(|error| format!("image preview: {error}"))?;
        if encoded.len() <= 256 * 1024 {
            return PrivateTemp::with_bytes("jpg", &encoded).map(Some);
        }
    }
    Err("image preview could not fit the 256 KiB limit".to_owned())
}

/// Network configuration the user can edit on the unlock screen. Persisted
/// as plain JSON next to the store — it holds the same information as
/// `kultd`'s command-line flags and **no secrets** (the store passphrase
/// and everything inside the store never touch this file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// Multiaddrs to listen on. The default binds QUIC + TCP on
    /// OS-assigned ports; pin a port here for port-forwarding setups.
    pub listen: Vec<String>,
    /// DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
    /// discovery then never leaves this node (mDNS still works).
    pub bootstrap: Vec<String>,
    /// Relay to reserve a circuit at when NAT-ed (defaults to the first
    /// bootstrap peer when unset).
    pub relay: Option<String>,
    /// Mailbox relays to check in with.
    pub mailboxes: Vec<String>,
    /// Volunteer bounded mailbox service for others.
    pub serve_mailbox: bool,
    /// Announce/discover on the local network (zero-config LAN delivery).
    pub mdns: bool,
    /// Also receive from a sneakernet spool directory.
    pub spool: Option<String>,
    /// Attach a Meshtastic radio on this USB-serial port (needs a build
    /// with the `meshtastic` feature).
    pub meshtastic_serial: Option<String>,
    /// Attach a Meshtastic radio via its network API (`host:4403`).
    pub meshtastic_tcp: Option<String>,
    /// Bridge third-party sealed traffic between mesh and internet
    /// (ADR-0009); active only while a radio is attached.
    pub bridge: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
                "/ip4/0.0.0.0/tcp/0".to_owned(),
            ],
            bootstrap: Vec::new(),
            relay: None,
            mailboxes: Vec::new(),
            serve_mailbox: false,
            mdns: true,
            spool: None,
            meshtastic_serial: None,
            meshtastic_tcp: None,
            bridge: true,
        }
    }
}

impl NetworkSettings {
    /// The settings file inside a data directory.
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("settings.json")
    }

    /// Load from `data_dir`, falling back to defaults when absent. A
    /// present-but-corrupt file is an error — silently reverting a user's
    /// network configuration would be a lie.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        match std::fs::read(Self::path(data_dir)) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("settings.json is corrupt: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("settings.json: {e}")),
        }
    }

    /// Persist to `data_dir` (creating it if needed).
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("data dir: {e}"))?;
        let json = serde_json::to_vec_pretty(self).expect("settings serialize");
        std::fs::write(Self::path(data_dir), json).map_err(|e| format!("settings.json: {e}"))
    }
}

/// A contact row for the UI.
#[derive(Clone, Debug, Serialize)]
pub struct UiContact {
    /// The contact's peer id (hex).
    pub peer: String,
    /// Local display name.
    pub name: String,
    /// Whether safety numbers were verified out-of-band.
    pub verified: bool,
}

/// One exact UTF-8 source range composed into local formatting.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct UiTextFormatHighlight {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
}

/// One inert formatted run for safe DOM construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFormattedTextRun {
    /// Exact text inserted with `textContent`.
    pub text: String,
    /// Stable style tokens.
    pub styles: Vec<String>,
}

/// One bounded formatted block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFormattedTextBlock {
    /// Stable semantic block token.
    pub kind: String,
    /// Zero-based list depth.
    pub depth: u8,
    /// Ordered-list ordinal, otherwise zero.
    pub ordinal: u32,
    /// Exact display runs.
    pub runs: Vec<UiFormattedTextRun>,
}

/// Complete local formatting result for the desktop shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFormattedText {
    /// Exact source, unchanged.
    pub source: String,
    /// Formatting-free readable copy text.
    pub plain_text: String,
    /// Bounded render-safe blocks.
    pub blocks: Vec<UiFormattedTextBlock>,
    /// Whether complexity forced literal rendering.
    pub used_fallback: bool,
}

impl From<kult_ffi::FormattedText> for UiFormattedText {
    fn from(formatted: kult_ffi::FormattedText) -> Self {
        Self {
            source: formatted.source,
            plain_text: formatted.plain_text,
            blocks: formatted
                .blocks
                .into_iter()
                .map(|block| UiFormattedTextBlock {
                    kind: match block.kind {
                        FfiTextFormatBlockKind::Paragraph => "paragraph",
                        FfiTextFormatBlockKind::Quote => "quote",
                        FfiTextFormatBlockKind::UnorderedListItem => "unordered_list_item",
                        FfiTextFormatBlockKind::OrderedListItem => "ordered_list_item",
                        FfiTextFormatBlockKind::CodeBlock => "code_block",
                    }
                    .to_owned(),
                    depth: block.depth,
                    ordinal: block.ordinal,
                    runs: block
                        .runs
                        .into_iter()
                        .map(|run| UiFormattedTextRun {
                            text: run.text,
                            styles: run
                                .styles
                                .into_iter()
                                .map(|style| match style {
                                    FfiTextFormatStyle::Emphasis => "emphasis",
                                    FfiTextFormatStyle::Strong => "strong",
                                    FfiTextFormatStyle::InlineCode => "inline_code",
                                    FfiTextFormatStyle::Highlight => "highlight",
                                })
                                .map(str::to_owned)
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
            used_fallback: formatted.used_fallback,
        }
    }
}

/// Render-safe canonical petname and local warning review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiContactNameAssessment {
    /// NFC value that will be stored after confirmation.
    pub normalized_name: String,
    /// Whether normalization changed the proposed scalar sequence.
    pub changed_by_normalization: bool,
    /// Stable warning codes for accessible shell copy.
    pub warnings: Vec<String>,
    /// Other contacts with the exact same canonical petname.
    pub duplicate_count: u32,
}

impl From<FfiContactNameAssessment> for UiContactNameAssessment {
    fn from(value: FfiContactNameAssessment) -> Self {
        Self {
            normalized_name: value.normalized_name,
            changed_by_normalization: value.changed_by_normalization,
            warnings: value
                .warnings
                .into_iter()
                .map(|warning| match warning {
                    FfiContactNameWarning::DuplicateName => "duplicate_name",
                    FfiContactNameWarning::ConfusableName => "confusable_name",
                    FfiContactNameWarning::BidirectionalControl => "bidirectional_control",
                    FfiContactNameWarning::InvisibleCharacter => "invisible_character",
                })
                .map(str::to_owned)
                .collect(),
            duplicate_count: value.duplicate_count,
        }
    }
}

/// Exact typed target for one private local custom icon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiCustomIconTarget {
    /// `contact`, `group`, `folder`, or `note_to_self`.
    pub kind: String,
    /// Stable target id, absent only for note-to-self.
    pub id: Option<String>,
}

impl UiCustomIconTarget {
    fn to_ffi(&self) -> Result<FfiCustomIconTarget, String> {
        let kind = match self.kind.as_str() {
            "contact" => FfiCustomIconTargetKind::Contact,
            "group" => FfiCustomIconTargetKind::Group,
            "folder" => FfiCustomIconTargetKind::Folder,
            "note_to_self" => FfiCustomIconTargetKind::NoteToSelf,
            _ => {
                return Err(
                    "custom icon target kind must be contact, group, folder, or note_to_self"
                        .to_owned(),
                )
            }
        };
        Ok(FfiCustomIconTarget {
            kind,
            id: self.id.clone(),
        })
    }

    fn from_ffi(target: FfiCustomIconTarget) -> Self {
        Self {
            kind: match target.kind {
                FfiCustomIconTargetKind::Contact => "contact",
                FfiCustomIconTargetKind::Group => "group",
                FfiCustomIconTargetKind::Folder => "folder",
                FfiCustomIconTargetKind::NoteToSelf => "note_to_self",
            }
            .to_owned(),
            id: target.id,
        }
    }
}

/// Optional exact square crop in oriented source pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct UiCustomIconCrop {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Non-zero width.
    pub width: u32,
    /// Equal non-zero height.
    pub height: u32,
}

/// Render-ready canonical local icon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiCustomIcon {
    /// Exact typed target.
    pub target: UiCustomIconTarget,
    /// Canonical `image/png` media type.
    pub media_type: String,
    /// Bounded local data URL for the dependency-free webview.
    pub data_url: String,
    /// Exact encoded PNG byte count.
    pub encoded_bytes: u64,
    /// Canonical width.
    pub width: u32,
    /// Canonical height.
    pub height: u32,
}

impl UiCustomIcon {
    fn from_ffi(icon: FfiCustomIcon) -> Self {
        let encoded_bytes = icon.bytes.len() as u64;
        let data_url = format!(
            "data:{};base64,{}",
            icon.media_type,
            base64::engine::general_purpose::STANDARD.encode(&icon.bytes)
        );
        Self {
            target: UiCustomIconTarget::from_ffi(icon.target),
            media_type: icon.media_type,
            data_url,
            encoded_bytes,
            width: icon.width,
            height: icon.height,
        }
    }
}

/// Current sealed custom-icon quota usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UiCustomIconUsage {
    /// Durable icon records.
    pub records: u64,
    /// Aggregate canonical PNG bytes.
    pub bytes: u64,
}

/// Exact typed conversation target for local folder operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiFolderTarget {
    /// `peer`, `group`, or `note_to_self`.
    pub kind: String,
    /// Stable peer/group id, absent for note-to-self.
    pub id: Option<String>,
}

impl UiFolderTarget {
    fn to_ffi(&self) -> Result<FfiFolderTarget, String> {
        let kind = match self.kind.as_str() {
            "peer" => FfiFolderTargetKind::Peer,
            "group" => FfiFolderTargetKind::Group,
            "note_to_self" => FfiFolderTargetKind::NoteToSelf,
            _ => return Err("folder target kind must be peer, group, or note_to_self".to_owned()),
        };
        Ok(FfiFolderTarget {
            kind,
            id: self.id.clone(),
        })
    }

    fn from_ffi(target: FfiFolderTarget) -> Self {
        Self {
            kind: match target.kind {
                FfiFolderTargetKind::Peer => "peer",
                FfiFolderTargetKind::Group => "group",
                FfiFolderTargetKind::NoteToSelf => "note_to_self",
            }
            .to_owned(),
            id: target.id,
        }
    }
}

/// Render-safe private folder definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFolder {
    /// Stable random 32-hex-character technical id.
    pub id: String,
    /// Exact UTF-8 folder text.
    pub name: String,
    /// Persisted manual order.
    pub order: u32,
}

impl UiFolder {
    fn from_ffi(folder: FfiFolder) -> Self {
        Self {
            id: folder.id,
            name: folder.name,
            order: folder.order,
        }
    }
}

/// One currently available conversation in folder output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFolderConversation {
    /// Exact typed target.
    pub target: UiFolderTarget,
    /// Current render-only local name, absent for note-to-self.
    pub display_name: Option<String>,
}

impl UiFolderConversation {
    fn from_ffi(value: FfiFolderConversation) -> Self {
        Self {
            target: UiFolderTarget::from_ffi(value.target),
            display_name: value.display_name,
        }
    }
}

/// Explicit virtual or stable-folder navigation selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiFolderSelection {
    /// `all`, `unfiled`, or `folder`.
    pub kind: String,
    /// Stable folder id only for `folder`.
    pub id: Option<String>,
}

impl UiFolderSelection {
    fn to_ffi(&self) -> Result<FfiFolderSelection, String> {
        let kind = match self.kind.as_str() {
            "all" => FfiFolderSelectionKind::All,
            "unfiled" => FfiFolderSelectionKind::Unfiled,
            "folder" => FfiFolderSelectionKind::Folder,
            _ => return Err("folder selection must be all, unfiled, or folder".to_owned()),
        };
        Ok(FfiFolderSelection {
            kind,
            id: self.id.clone(),
        })
    }

    fn from_ffi(value: FfiFolderSelection) -> Self {
        Self {
            kind: match value.kind {
                FfiFolderSelectionKind::All => "all",
                FfiFolderSelectionKind::Unfiled => "unfiled",
                FfiFolderSelectionKind::Folder => "folder",
            }
            .to_owned(),
            id: value.id,
        }
    }
}

/// Render-safe stale folder-assignment cleanup row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiStaleFolder {
    /// Stable technical folder id.
    pub folder: String,
    /// Exact typed target.
    pub target: UiFolderTarget,
    /// Stable diagnostic reason.
    pub reason: &'static str,
}

impl UiStaleFolder {
    fn from_ffi(value: FfiStaleFolder) -> Self {
        Self {
            folder: value.folder,
            target: UiFolderTarget::from_ffi(value.target),
            reason: match value.reason {
                kult_ffi::StaleFolderReason::MissingFolder => "missing_folder",
                kult_ffi::StaleFolderReason::UnavailableConversation => "unavailable_conversation",
                kult_ffi::StaleFolderReason::MissingFolderAndConversation => {
                    "missing_folder_and_conversation"
                }
            },
        }
    }
}

/// Deterministic folder-first navigation composed with label filtering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiFolderConversationResult {
    /// Exact applied folder selection.
    pub selection: UiFolderSelection,
    /// Available selected label ids.
    pub selected_labels: Vec<String>,
    /// Selected label ids whose definitions are unavailable.
    pub unavailable_labels: Vec<String>,
    /// Conversations matching both controls.
    pub conversations: Vec<UiFolderConversation>,
}

impl UiFolderConversationResult {
    fn from_ffi(value: FfiFolderConversationResult) -> Self {
        Self {
            selection: UiFolderSelection::from_ffi(value.selection),
            selected_labels: value.selected_labels,
            unavailable_labels: value.unavailable_labels,
            conversations: value
                .conversations
                .into_iter()
                .map(UiFolderConversation::from_ffi)
                .collect(),
        }
    }
}

/// Exact typed conversation target for local label operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiLabelTarget {
    /// `peer`, `group`, or `note_to_self`.
    pub kind: String,
    /// Stable peer/group id, absent for note-to-self.
    pub id: Option<String>,
}

impl UiLabelTarget {
    fn to_ffi(&self) -> Result<FfiLabelTarget, String> {
        let kind = match self.kind.as_str() {
            "peer" => FfiLabelTargetKind::Peer,
            "group" => FfiLabelTargetKind::Group,
            "note_to_self" => FfiLabelTargetKind::NoteToSelf,
            _ => return Err("label target kind must be peer, group, or note_to_self".to_owned()),
        };
        Ok(FfiLabelTarget {
            kind,
            id: self.id.clone(),
        })
    }

    fn from_ffi(target: FfiLabelTarget) -> Self {
        Self {
            kind: match target.kind {
                FfiLabelTargetKind::Peer => "peer",
                FfiLabelTargetKind::Group => "group",
                FfiLabelTargetKind::NoteToSelf => "note_to_self",
            }
            .to_owned(),
            id: target.id,
        }
    }
}

/// Render-safe private label definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiLabel {
    /// Stable random 32-hex-character technical id.
    pub id: String,
    /// Exact UTF-8 label text.
    pub name: String,
    /// Canonical safe color token.
    pub color: String,
    /// Stable durable insertion order.
    pub order: u32,
}

impl UiLabel {
    fn from_ffi(label: FfiLabel) -> Self {
        Self {
            id: label.id,
            name: label.name,
            color: label.color,
            order: label.order,
        }
    }
}

/// One currently available conversation in label output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiLabelConversation {
    /// Exact typed target.
    pub target: UiLabelTarget,
    /// Current render-only local name, absent for note-to-self.
    pub display_name: Option<String>,
}

impl UiLabelConversation {
    fn from_ffi(value: FfiLabelConversation) -> Self {
        Self {
            target: UiLabelTarget::from_ffi(value.target),
            display_name: value.display_name,
        }
    }
}

/// Render-safe stale membership cleanup row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiStaleLabel {
    /// Stable technical label id.
    pub label: String,
    /// Exact typed target.
    pub target: UiLabelTarget,
    /// Stable diagnostic reason.
    pub reason: &'static str,
}

impl UiStaleLabel {
    fn from_ffi(value: FfiStaleLabel) -> Self {
        Self {
            label: value.label,
            target: UiLabelTarget::from_ffi(value.target),
            reason: match value.reason {
                kult_ffi::StaleLabelReason::MissingLabel => "missing_label",
                kult_ffi::StaleLabelReason::UnavailableConversation => "unavailable_conversation",
                kult_ffi::StaleLabelReason::MissingLabelAndConversation => {
                    "missing_label_and_conversation"
                }
            },
        }
    }
}

/// Deterministic local any/all label filter output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiLabelFilterResult {
    /// Canonically deduplicated available selections.
    pub selected: Vec<String>,
    /// Selected ids that no longer exist.
    pub unavailable_selected: Vec<String>,
    /// Eligible matching targets.
    pub conversations: Vec<UiLabelConversation>,
}

impl UiLabelFilterResult {
    fn from_ffi(value: FfiLabelFilterResult) -> Self {
        Self {
            selected: value.selected,
            unavailable_selected: value.unavailable_selected,
            conversations: value
                .conversations
                .into_iter()
                .map(UiLabelConversation::from_ffi)
                .collect(),
        }
    }
}

/// Exact typed conversation target for private local pin operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPinTarget {
    /// `peer`, `group`, or `note_to_self`.
    pub kind: String,
    /// Stable peer/group id, absent for note-to-self.
    pub id: Option<String>,
}

impl UiPinTarget {
    fn to_ffi(&self) -> Result<FfiPinTarget, String> {
        let kind = match self.kind.as_str() {
            "peer" => FfiPinTargetKind::Peer,
            "group" => FfiPinTargetKind::Group,
            "note_to_self" => FfiPinTargetKind::NoteToSelf,
            _ => return Err("pin target kind must be peer, group, or note_to_self".to_owned()),
        };
        Ok(FfiPinTarget {
            kind,
            id: self.id.clone(),
        })
    }

    fn from_ffi(target: FfiPinTarget) -> Self {
        Self {
            kind: match target.kind {
                FfiPinTargetKind::Peer => "peer",
                FfiPinTargetKind::Group => "group",
                FfiPinTargetKind::NoteToSelf => "note_to_self",
            }
            .to_owned(),
            id: target.id,
        }
    }
}

/// Render-safe durable private local pin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiPin {
    /// Exact typed target.
    pub target: UiPinTarget,
    /// Current local display name when available.
    pub display_name: Option<String>,
    /// Persisted manual order.
    pub order: u32,
    /// Whether the exact target is currently available.
    pub active: bool,
}

impl UiPin {
    fn from_ffi(value: FfiPin) -> Self {
        Self {
            target: UiPinTarget::from_ffi(value.target),
            display_name: value.display_name,
            order: value.order,
            active: value.active,
        }
    }
}

/// One available row after folder, label, and pin composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiPinConversation {
    /// Exact typed target.
    pub target: UiPinTarget,
    /// Current local display name.
    pub display_name: Option<String>,
    /// Whether this row is in the leading pinned block.
    pub pinned: bool,
    /// Persisted order when pinned.
    pub pin_order: Option<u32>,
    /// Latest local message activity.
    pub recent_activity: u64,
}

impl UiPinConversation {
    fn from_ffi(value: FfiPinConversation) -> Self {
        Self {
            target: UiPinTarget::from_ffi(value.target),
            display_name: value.display_name,
            pinned: value.pinned,
            pin_order: value.pin_order,
            recent_activity: value.recent_activity,
        }
    }
}

/// Deterministic folder-first, label-second, pin-aware navigation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiPinConversationResult {
    /// Applied folder selection.
    pub selection: UiFolderSelection,
    /// Available selected label ids.
    pub selected_labels: Vec<String>,
    /// Selected unavailable label ids.
    pub unavailable_labels: Vec<String>,
    /// Ordered eligible conversations.
    pub conversations: Vec<UiPinConversation>,
}

impl UiPinConversationResult {
    fn from_ffi(value: FfiPinConversationResult) -> Self {
        Self {
            selection: UiFolderSelection::from_ffi(value.selection),
            selected_labels: value.selected_labels,
            unavailable_labels: value.unavailable_labels,
            conversations: value
                .conversations
                .into_iter()
                .map(UiPinConversation::from_ffi)
                .collect(),
        }
    }
}

/// A message row for the UI. `state` is one of `queued`, `sent`,
/// `delivered`, `received` — never anything the node didn't report.
#[derive(Clone, Debug, Serialize)]
pub struct UiEditVersion {
    /// Original content id for revision zero, otherwise edit-event id (hex).
    pub id: String,
    /// Zero for the original, positive for an immutable edit.
    pub revision: u64,
    /// Local presentation timestamp.
    pub timestamp: u64,
    /// Exact authenticated text for this version.
    pub body: String,
}

/// A message row for the UI. `state` is one of `queued`, `sent`,
/// `delivered`, `received` — never anything the node didn't report.
#[derive(Clone, Debug, Serialize)]
pub struct UiMessage {
    /// Message record id (hex).
    pub id: String,
    /// The conversation peer (hex).
    pub peer: String,
    /// Sent by this device (vs. received).
    pub outbound: bool,
    /// Delivery state, verbatim from the node.
    pub state: &'static str,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub body: String,
    /// `legacy_text`, `text`, `unsupported`, or `malformed`.
    pub content_kind: &'static str,
    /// Exact authenticated local expiry for ephemeral content.
    pub expires_at: Option<u64>,
    /// Whether an immutable edit wins over the original.
    pub edited: bool,
    /// Winning positive revision, or zero for the original.
    pub edit_revision: u64,
    /// Original plus valid immutable edits in convergence order.
    pub versions: Vec<UiEditVersion>,
}

/// One sealed, local-only note-to-self entry. It intentionally has no
/// transport direction or delivery state because it never leaves the node.
#[derive(Clone, Debug, Serialize)]
pub struct UiNoteMessage {
    /// Message record id (hex).
    pub id: String,
    /// Stable reserved conversation identity shared by every shell.
    pub conversation: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Note text.
    pub body: String,
}

/// One editable/cancellable scheduled outbox entry.
#[derive(Clone, Debug, Serialize)]
pub struct UiScheduledMessage {
    /// Stable message id (hex).
    pub id: String,
    /// `peer` or `group`.
    pub conversation: &'static str,
    /// Peer or group id (hex).
    pub destination: String,
    /// Unix time when the schedule was created.
    pub created_at: u64,
    /// Absolute UTC Unix send instant.
    pub not_before: u64,
    /// Message text.
    pub body: String,
    /// Explicit state label for shell rendering.
    pub state: &'static str,
}

/// A sender-key group row for the desktop UI. Secret material and sender
/// chains never cross into the shell.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroup {
    /// Group id (hex).
    pub id: String,
    /// Creator-controlled display name.
    pub name: String,
    /// Managing member's peer id (hex).
    pub creator: String,
    /// Full roster, this node included (hex peer ids).
    pub members: Vec<String>,
}

/// One member's honest delivery state for an outbound group message.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroupDelivery {
    /// Recipient peer id (hex).
    pub peer: String,
    /// `queued`, `sent`, or `delivered`, verbatim from the node.
    pub state: &'static str,
}

/// One semantic Mention span rendered by the desktop shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct UiMentionSpan {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
    /// Exact target peer id (hex).
    pub target: String,
}

/// One current member preventing semantic Mention send.
#[derive(Clone, Debug, Serialize)]
pub struct UiMentionIssue {
    /// Exact member peer id (hex).
    pub peer: String,
    /// `unknown` or `unsupported`.
    pub reason: &'static str,
}

/// Current conservative Mention capability verdict and review binding.
#[derive(Clone, Debug, Serialize)]
pub struct UiMentionCapability {
    /// Group id (hex).
    pub group: String,
    /// Whether exact typed Mention may be sent now.
    pub supported: bool,
    /// Opaque roster/capability/display review token.
    pub review_token: String,
    /// Blocking current members.
    pub issues: Vec<UiMentionIssue>,
}

/// One stable poll choice with a visible local tally.
#[derive(Clone, Debug, Serialize)]
pub struct UiPollOption {
    /// Stable option id (hex).
    pub id: String,
    /// Exact authenticated UTF-8 label.
    pub text: String,
    /// Accepted visible vote heads.
    pub votes: u32,
    /// Whether the local identity selected this option.
    pub selected_by_me: bool,
}

/// One visible authenticated vote head.
#[derive(Clone, Debug, Serialize)]
pub struct UiPollVote {
    /// Authenticated voter peer id (hex).
    pub voter: String,
    /// Stable selected option id (hex).
    pub option_id: String,
    /// Positive voter-local revision.
    pub revision: u64,
}

/// One render-safe group poll card.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroupPoll {
    /// Exact group id (hex).
    pub group: String,
    /// Authenticated creator peer id (hex).
    pub author: String,
    /// Stable poll id (hex).
    pub id: String,
    /// Exact authenticated question.
    pub question: String,
    /// Fixed creation-time electorate.
    pub eligible_voters: Vec<String>,
    /// Stable ordered choices and tallies.
    pub options: Vec<UiPollOption>,
    /// Visible accepted vote heads.
    pub votes: Vec<UiPollVote>,
    /// Whether the creator finalized the poll.
    pub closed: bool,
    /// Whether this identity belongs to the electorate.
    pub eligible: bool,
    /// Whether this identity can close the poll.
    pub can_close: bool,
    /// Honest product policy; always true for C5.
    pub votes_visible: bool,
    /// Honest product policy; always false for C5.
    pub anonymous: bool,
    /// `manual_creator_snapshot`.
    pub close_policy: String,
}

impl UiGroupPoll {
    fn from_ffi(poll: FfiGroupPoll) -> Self {
        Self {
            group: poll.group,
            author: poll.author,
            id: poll.id,
            question: poll.question,
            eligible_voters: poll.eligible_voters,
            options: poll
                .options
                .into_iter()
                .map(|option| UiPollOption {
                    id: option.id,
                    text: option.text,
                    votes: option.votes,
                    selected_by_me: option.selected_by_me,
                })
                .collect(),
            votes: poll
                .votes
                .into_iter()
                .map(|vote| UiPollVote {
                    voter: vote.voter,
                    option_id: vote.option_id,
                    revision: vote.revision,
                })
                .collect(),
            closed: poll.closed,
            eligible: poll.eligible,
            can_close: poll.can_close,
            votes_visible: poll.votes_visible,
            anonymous: poll.anonymous,
            close_policy: poll.close_policy,
        }
    }
}

/// A group message row for the desktop conversation view.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroupMessage {
    /// Group message record id (hex).
    pub id: String,
    /// Group id (hex).
    pub group: String,
    /// Sending member's peer id (hex).
    pub sender: String,
    /// Sent by this device (vs. received).
    pub outbound: bool,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub body: String,
    /// `legacy_text`, `text`, `unsupported`, or `malformed`.
    pub content_kind: &'static str,
    /// Exact authenticated local expiry for ephemeral content.
    pub expires_at: Option<u64>,
    /// Stable semantic Mention spans; empty for other content.
    pub mention_spans: Vec<UiMentionSpan>,
    /// Whether an immutable edit wins over the original.
    pub edited: bool,
    /// Winning positive revision, or zero for the original.
    pub edit_revision: u64,
    /// Original plus valid immutable edits in convergence order.
    pub versions: Vec<UiEditVersion>,
    /// Per-recipient states for outbound messages; empty for inbound.
    pub deliveries: Vec<UiGroupDelivery>,
}

/// A point-in-time node snapshot for the status bar.
#[derive(Clone, Debug, Serialize)]
pub struct UiStatus {
    /// This node's human-shareable kult address.
    pub address: String,
    /// This node's peer id (hex).
    pub peer: String,
    /// Live listen addresses (circuit addresses included once reserved).
    pub listen: Vec<String>,
    /// Peers currently visible on the LAN via mDNS.
    pub lan_peers: Vec<String>,
    /// `public`, `private`, or `unknown`.
    pub nat: &'static str,
    /// Outbound messages not yet delivered.
    pub queued: u64,
    /// Text waiting for a future UTC activation instant.
    pub scheduled: u64,
    /// Third-party envelopes buffered for mesh↔internet bridging.
    pub transit: u64,
    /// Stored contacts.
    pub contacts: u64,
}

/// The safety number screen's payload: digits to read aloud, and a QR of
/// the raw comparison value to scan.
#[derive(Clone, Debug, Serialize)]
pub struct UiSafetyNumber {
    /// 60 decimal digits.
    pub digits: String,
    /// The digits grouped 5-at-a-time for display.
    pub display: String,
    /// QR of the comparison value — identical on both ends.
    pub qr_svg: String,
}

/// An exported prekey bundle: hex to paste (interoperable with
/// `kult bundle` / `kult add`), QR carrying the same hex to scan.
#[derive(Clone, Debug, Serialize)]
pub struct UiBundle {
    /// The bundle bytes, lowercase hex.
    pub hex: String,
    /// QR carrying the same hex (uppercase, alphanumeric mode).
    pub qr_svg: String,
}

/// A delivery hint as the UI edits it: a `kind` tag plus one string value.
#[derive(Clone, Debug, Deserialize)]
pub struct UiHint {
    /// `multiaddr`, `relay`, `spool`, or `mesh`.
    pub kind: String,
    /// The multiaddr / path / mesh node number (`broadcast` floods).
    pub value: String,
}

impl UiHint {
    fn to_ffi(&self) -> Result<Hint, String> {
        let value = self.value.trim();
        if value.is_empty() {
            return Err("hint value must not be empty".to_owned());
        }
        Ok(match self.kind.as_str() {
            "multiaddr" => Hint::Multiaddr {
                addr: value.to_owned(),
            },
            "relay" => Hint::Relay {
                addr: value.to_owned(),
            },
            "spool" => Hint::Spool {
                path: value.to_owned(),
            },
            "mesh" => Hint::Mesh {
                node: if value.eq_ignore_ascii_case("broadcast") {
                    u32::MAX
                } else {
                    value.parse().map_err(|_| {
                        format!("mesh hint must be a node number or `broadcast`, got `{value}`")
                    })?
                },
            },
            other => return Err(format!("unknown hint kind `{other}`")),
        })
    }
}

/// Render-safe progress for one attachment object.
#[derive(Clone, Debug, Serialize)]
pub struct UiAttachmentObject {
    /// Whether this is the optional preview rather than the primary object.
    pub preview: bool,
    /// Exact authenticated object size.
    pub total_bytes: u64,
    /// Bytes represented by durably verified chunks.
    pub verified_bytes: u64,
    /// Authenticated but untrusted media-type display hint.
    pub media_type: String,
    /// Optional sanitized display basename.
    pub filename: Option<String>,
    /// Shared conservative local file-presentation decision.
    pub presentation: UiAttachmentFilePresentation,
    /// Durable object lifecycle state.
    pub state: &'static str,
}

/// Stable webview tokens for the shared C1 attachment policy.
#[derive(Clone, Debug, Serialize)]
pub struct UiAttachmentFilePresentation {
    /// Inert icon/label category.
    pub kind: &'static str,
    /// `protected_media`, `external_open`, or `export_only`.
    pub open_policy: &'static str,
    /// Canonically ordered caution tokens.
    pub warnings: Vec<&'static str>,
}

impl UiAttachmentFilePresentation {
    fn from_ffi(value: FfiAttachmentFilePresentation) -> Self {
        Self {
            kind: match value.kind {
                FfiAttachmentFileKind::Image => "image",
                FfiAttachmentFileKind::Audio => "audio",
                FfiAttachmentFileKind::Video => "video",
                FfiAttachmentFileKind::Document => "document",
                FfiAttachmentFileKind::Archive => "archive",
                FfiAttachmentFileKind::Executable => "executable",
                FfiAttachmentFileKind::Other => "other",
            },
            open_policy: match value.open_policy {
                FfiAttachmentOpenPolicy::ProtectedMedia => "protected_media",
                FfiAttachmentOpenPolicy::ExternalOpen => "external_open",
                FfiAttachmentOpenPolicy::ExportOnly => "export_only",
            },
            warnings: value
                .warnings
                .into_iter()
                .map(|warning| match warning {
                    FfiAttachmentFileWarning::MediaTypeMismatch => "media_type_mismatch",
                    FfiAttachmentFileWarning::DangerousType => "dangerous_type",
                    FfiAttachmentFileWarning::UnrecognizedType => "unrecognized_type",
                    FfiAttachmentFileWarning::MissingFilename => "missing_filename",
                })
                .collect(),
        }
    }
}

/// Render-safe attachment transfer state for the webview event stream.
#[derive(Clone, Debug, Serialize)]
pub struct UiAttachment {
    /// Random local transfer id (hex).
    pub transfer_id: String,
    /// Peer serving or being served (hex).
    pub peer: String,
    /// `pairwise` or `group`.
    pub conversation: &'static str,
    /// Group id for group attachments; absent for pairwise transfers.
    pub group: Option<String>,
    /// `inbound` or `outbound` on this device.
    pub direction: &'static str,
    /// Original manifest author (hex).
    pub author: String,
    /// Stable encrypted content id (hex).
    pub content_id: String,
    /// Durable transfer lifecycle state.
    pub state: &'static str,
    /// Whether first-open consumption governs this transfer.
    pub view_once: bool,
    /// Exact fallback deadline.
    pub expires_at: Option<u64>,
    /// Whether it is terminal after first open or expiry.
    pub consumed: bool,
    /// Primary object followed by an optional preview.
    pub objects: Vec<UiAttachmentObject>,
}

/// Bounded protected playback material plus locally derived presentation data.
#[derive(Clone, Debug, Serialize)]
pub struct UiAudioMedia {
    /// Bounded canonical audio bytes for the webview's explicit player.
    pub data_url: String,
    /// Exact locally derived duration.
    pub duration_ms: u64,
    /// Sixty-four local peak amplitudes; never sent over the network.
    pub waveform: Vec<u16>,
}

impl UiAttachment {
    fn from_ffi(attachment: Attachment) -> Self {
        Self {
            transfer_id: attachment.transfer_id,
            peer: attachment.peer,
            conversation: attachment_conversation_str(attachment.conversation),
            group: attachment.group,
            direction: attachment_direction_str(attachment.direction),
            author: attachment.author,
            content_id: attachment.content_id,
            state: attachment_state_str(attachment.state),
            view_once: attachment.view_once,
            expires_at: attachment.expires_at,
            consumed: attachment.consumed,
            objects: attachment
                .objects
                .into_iter()
                .map(|object| UiAttachmentObject {
                    preview: object.preview,
                    total_bytes: object.total_bytes,
                    verified_bytes: object.verified_bytes,
                    media_type: object.media_type,
                    filename: object.filename,
                    presentation: UiAttachmentFilePresentation::from_ffi(object.presentation),
                    state: attachment_state_str(object.state),
                })
                .collect(),
        }
    }
}

/// A node event as the webview receives it (`type` tag plus fields).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiEvent {
    /// A scheduled message was created or edited.
    ScheduledMessageUpdated {
        /// Stable message id (hex).
        id: String,
    },
    /// A scheduled message was cancelled before activation.
    ScheduledMessageCancelled {
        /// Stable message id (hex).
        id: String,
    },
    /// A scheduled message entered the encrypted delivery queue.
    ScheduledMessageActivated {
        /// Stable message id (hex).
        id: String,
    },
    /// A message record changed delivery state.
    DeliveryUpdated {
        /// Message record id (hex).
        id: String,
        /// The new state (`queued`/`sent`/`delivered`).
        state: &'static str,
    },
    /// An inbound message was decrypted and stored.
    MessageReceived {
        /// Sender peer id (hex).
        peer: String,
        /// Message record id (hex).
        id: String,
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Decrypted body.
        body: String,
        /// Explicit content interpretation.
        content_kind: &'static str,
        /// Exact deadline for ephemeral content.
        expires_at: Option<u64>,
    },
    /// An inbound pairwise Edit was stored; refresh the exact target.
    MessageEdited {
        /// Pairwise peer that authored the edit and original.
        peer: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
    },
    /// A sealed local-only note was appended.
    NoteToSelfMessageAdded {
        /// Stable reserved conversation identity.
        conversation: String,
        /// Message record id (hex).
        id: String,
        /// Local creation time (Unix seconds).
        timestamp: u64,
        /// Note text.
        body: String,
    },
    /// An unknown peer completed a handshake; a contact stub exists now.
    ContactAdded {
        /// The new peer (hex).
        peer: String,
    },
    /// A stored contact's sealed private local petname changed.
    ContactRenamed {
        /// Exact stable peer id (hex).
        peer: String,
        /// Canonical NFC petname now stored locally.
        name: String,
    },
    /// A ratchet session was (re-)established from an inbound handshake —
    /// for a known contact this means their key or device changed.
    SessionEstablished {
        /// The peer (hex).
        peer: String,
    },
    /// An outbound message is held: only duty-cycle-limited (LoRa)
    /// carriers currently reach the recipient.
    AwaitingFasterLink {
        /// Message record id (hex).
        id: String,
    },
    /// The authoritative time-bounded carrier verdict for a contact changed.
    CarrierCapabilityChanged {
        /// Contact peer id (hex).
        peer: String,
        /// `realtime`, `bulk`, `mesh_only`, or `offline_or_unknown`.
        capability: &'static str,
        /// Unix time at which transports were probed.
        observed_at: u64,
        /// Unix time at which the verdict stops being authoritative.
        expires_at: u64,
    },
    /// A group was created, joined, re-keyed, re-rostered, or left.
    GroupUpdated {
        /// Group id (hex).
        group: String,
    },
    /// An inbound group message was decrypted and stored.
    GroupMessageReceived {
        /// Group id (hex).
        group: String,
        /// Sending member's peer id (hex).
        sender: String,
        /// Group message record id (hex).
        id: String,
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Decrypted body.
        body: String,
        /// Explicit content interpretation.
        content_kind: &'static str,
        /// Exact deadline for ephemeral content.
        expires_at: Option<u64>,
        /// Stable semantic Mention spans; empty for other content.
        mention_spans: Vec<UiMentionSpan>,
    },
    /// An inbound group Edit was stored; refresh the exact target.
    GroupMessageEdited {
        /// Group id (hex).
        group: String,
        /// Authenticated edit/original author (hex).
        sender: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
    },
    /// A poll creation, vote, or closure changed a group poll card.
    PollUpdated {
        /// Group id (hex).
        group: String,
        /// Authenticated poll creator (hex).
        poll_author: String,
        /// Stable poll id (hex).
        poll_id: String,
    },
    /// Ephemeral content became terminal on this installation.
    EphemeralRemoved {
        /// `pairwise` or `group`.
        conversation_kind: String,
        /// Peer or group id.
        conversation_id: String,
        /// Authenticated author id.
        author: String,
        /// Content id.
        content_id: String,
        /// `expired` or `consumed`.
        reason: String,
    },
    /// A canonical group Mention targets the exact local peer.
    MentionReceived {
        /// Protected group history record id. No message text is duplicated.
        id: String,
    },
    /// One member's copy of an outbound group message changed state.
    GroupDeliveryUpdated {
        /// Group message record id (hex).
        id: String,
        /// Member peer id (hex).
        peer: String,
        /// Delivery state for this member's copy.
        state: &'static str,
    },
    /// Attachment offer, consent, progress, completion, or terminal state
    /// changed.
    AttachmentUpdated {
        /// Current render-safe transfer state.
        attachment: UiAttachment,
    },
    /// Private local appearance preference changed.
    ThemeChanged,
    /// Private local custom icons changed.
    CustomIconsChanged,
    /// Private local folder definitions, order, or assignments changed.
    FoldersChanged,
    /// Private local label definitions or memberships changed.
    LabelsChanged,
    /// Private local pin definitions or order changed.
    PinsChanged,
}

impl UiEvent {
    fn from_ffi(event: Event) -> Self {
        match event {
            Event::ScheduledMessageUpdated { id } => Self::ScheduledMessageUpdated { id },
            Event::ScheduledMessageCancelled { id } => Self::ScheduledMessageCancelled { id },
            Event::ScheduledMessageActivated { id } => Self::ScheduledMessageActivated { id },
            Event::DeliveryUpdated { id, state } => Self::DeliveryUpdated {
                id,
                state: state_str(state),
            },
            Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content_kind,
                expires_at,
            } => Self::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content_kind: content_kind_str(content_kind),
                expires_at,
            },
            Event::MessageEdited {
                peer,
                target_content_id,
            } => Self::MessageEdited {
                peer,
                target_content_id,
            },
            Event::NoteToSelfMessageAdded {
                conversation,
                id,
                timestamp,
                body,
            } => Self::NoteToSelfMessageAdded {
                conversation,
                id,
                timestamp,
                body,
            },
            Event::ContactAdded { peer } => Self::ContactAdded { peer },
            Event::ContactRenamed { peer, name } => Self::ContactRenamed { peer, name },
            Event::SessionEstablished { peer } => Self::SessionEstablished { peer },
            Event::AwaitingFasterLink { id } => Self::AwaitingFasterLink { id },
            Event::CarrierCapabilityChanged { snapshot } => Self::CarrierCapabilityChanged {
                peer: snapshot.peer,
                capability: carrier_capability_str(snapshot.capability),
                observed_at: snapshot.observed_at,
                expires_at: snapshot.expires_at,
            },
            Event::GroupUpdated { group } => Self::GroupUpdated { group },
            Event::GroupMessageReceived {
                group,
                sender,
                id,
                timestamp,
                body,
                content_kind,
                mention_spans,
                expires_at,
            } => Self::GroupMessageReceived {
                group,
                sender,
                id,
                timestamp,
                body,
                content_kind: content_kind_str(content_kind),
                expires_at,
                mention_spans: mention_spans
                    .into_iter()
                    .map(|span| UiMentionSpan {
                        start: span.start,
                        end: span.end,
                        target: span.target,
                    })
                    .collect(),
            },
            Event::GroupMessageEdited {
                group,
                sender,
                target_content_id,
            } => Self::GroupMessageEdited {
                group,
                sender,
                target_content_id,
            },
            Event::PollUpdated {
                group,
                poll_author,
                poll_id,
            } => Self::PollUpdated {
                group,
                poll_author,
                poll_id,
            },
            Event::EphemeralRemoved {
                conversation_kind,
                conversation_id,
                author,
                content_id,
                reason,
            } => Self::EphemeralRemoved {
                conversation_kind,
                conversation_id,
                author,
                content_id,
                reason,
            },
            Event::MentionReceived { id } => Self::MentionReceived { id },
            Event::GroupDeliveryUpdated { id, peer, state } => Self::GroupDeliveryUpdated {
                id,
                peer,
                state: state_str(state),
            },
            Event::AttachmentUpdated { attachment } => Self::AttachmentUpdated {
                attachment: UiAttachment::from_ffi(attachment),
            },
            Event::ThemeChanged => Self::ThemeChanged,
            Event::CustomIconsChanged => Self::CustomIconsChanged,
            Event::FoldersChanged => Self::FoldersChanged,
            Event::LabelsChanged => Self::LabelsChanged,
            Event::PinsChanged => Self::PinsChanged,
        }
    }
}

/// Canonical appearance choice used by the dependency-free webview.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiThemePreference {
    /// Follow the operating system live.
    #[default]
    System,
    /// Force the light palette.
    Light,
    /// Force the dark palette.
    Dark,
}

/// Current sealed theme choice plus first-run persistence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UiThemeInfo {
    /// Canonical choice.
    pub preference: UiThemePreference,
    /// Whether the sealed F5 record already exists.
    pub persisted: bool,
}

impl UiThemePreference {
    fn from_ffi(value: FfiThemePreference) -> Self {
        match value {
            FfiThemePreference::System => Self::System,
            FfiThemePreference::Light => Self::Light,
            FfiThemePreference::Dark => Self::Dark,
        }
    }

    fn into_ffi(self) -> FfiThemePreference {
        match self {
            Self::System => FfiThemePreference::System,
            Self::Light => FfiThemePreference::Light,
            Self::Dark => FfiThemePreference::Dark,
        }
    }
}

fn state_str(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Queued => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Received => "received",
    }
}

fn content_kind_str(kind: ContentKind) -> &'static str {
    match kind {
        ContentKind::LegacyText => "legacy_text",
        ContentKind::Text => "text",
        ContentKind::Attachment => "attachment",
        ContentKind::Mention => "mention",
        ContentKind::DisappearingText => "disappearing_text",
        ContentKind::ViewOnceAttachment => "view_once_attachment",
        ContentKind::Poll => "poll",
        ContentKind::Unsupported => "unsupported",
        ContentKind::Malformed => "malformed",
    }
}

fn attachment_conversation_str(conversation: AttachmentConversation) -> &'static str {
    match conversation {
        AttachmentConversation::Pairwise => "pairwise",
        AttachmentConversation::Group => "group",
    }
}

fn attachment_direction_str(direction: AttachmentDirection) -> &'static str {
    match direction {
        AttachmentDirection::Inbound => "inbound",
        AttachmentDirection::Outbound => "outbound",
    }
}

fn attachment_state_str(state: AttachmentState) -> &'static str {
    match state {
        AttachmentState::Offered => "offered",
        AttachmentState::AwaitingConsent => "awaiting_consent",
        AttachmentState::Queued => "queued",
        AttachmentState::Transferring => "transferring",
        AttachmentState::Paused => "paused",
        AttachmentState::Complete => "complete",
        AttachmentState::Rejected => "rejected",
        AttachmentState::Cancelled => "cancelled",
        AttachmentState::Corrupt => "corrupt",
        AttachmentState::Unavailable => "unavailable",
    }
}

fn carrier_capability_str(capability: CarrierCapability) -> &'static str {
    match capability {
        CarrierCapability::Realtime => "realtime",
        CarrierCapability::Bulk => "bulk",
        CarrierCapability::MeshOnly => "mesh_only",
        CarrierCapability::OfflineOrUnknown => "offline_or_unknown",
    }
}

/// Where the shell delivers node events (the Tauri app emits them to the
/// webview; tests collect them in a `Vec`).
pub type EventSink = Box<dyn Fn(UiEvent) + Send + Sync>;

/// Adapter: `kult-ffi`'s listener trait onto an [`EventSink`].
struct Forwarder(EventSink);

impl EventListener for Forwarder {
    fn on_event(&self, event: Event) {
        (self.0)(UiEvent::from_ffi(event));
    }
}

/// A running node plus the shell-side conveniences the UI needs.
pub struct Session {
    node: Arc<KultNode>,
    pending_images: Mutex<HashMap<String, PendingImageEdit>>,
    opened_attachments: Mutex<HashMap<String, PrivateTemp>>,
}

impl Session {
    /// Open (or create on first run) the store in `data_dir` and start the
    /// node. Blocking — call off the UI thread. `kdf` is the Argon2id cost
    /// profile for store *creation* (the app passes the desktop profile;
    /// tests pass the cheaper mobile one, exactly like the core's own).
    pub fn open(
        data_dir: &Path,
        passphrase: String,
        settings: &NetworkSettings,
        kdf: KdfChoice,
        sink: EventSink,
    ) -> Result<Self, String> {
        cleanup_media_temps();
        let config = build_config(data_dir, passphrase, settings, kdf);
        let node = KultNode::start(config, Box::new(Forwarder(sink))).map_err(|e| e.to_string())?;
        Ok(Self {
            node,
            pending_images: Mutex::new(HashMap::new()),
            opened_attachments: Mutex::new(HashMap::new()),
        })
    }

    /// First run only: restore from an encrypted backup file instead of
    /// creating a fresh identity, then start.
    pub fn restore(
        data_dir: &Path,
        passphrase: String,
        backup_path: String,
        mnemonic: String,
        settings: &NetworkSettings,
        kdf: KdfChoice,
        sink: EventSink,
    ) -> Result<Self, String> {
        cleanup_media_temps();
        let config = build_config(data_dir, passphrase, settings, kdf);
        let node = KultNode::restore(config, backup_path, mnemonic, Box::new(Forwarder(sink)))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            node,
            pending_images: Mutex::new(HashMap::new()),
            opened_attachments: Mutex::new(HashMap::new()),
        })
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.node.address()
    }

    /// Render exact source into the shared bounded and inert text model.
    pub fn format_text(
        &self,
        source: String,
        highlights: Vec<UiTextFormatHighlight>,
    ) -> Result<UiFormattedText, String> {
        let highlights = highlights
            .into_iter()
            .map(|highlight| FfiTextFormatHighlight {
                start: highlight.start,
                end: highlight.end,
            })
            .collect();
        self.node
            .format_text(source, highlights)
            .map(Into::into)
            .map_err(|error| error.to_string())
    }

    /// A QR of the kult address (for adding this node by address).
    pub fn address_qr(&self) -> Result<String, String> {
        qr::svg(self.node.address().as_bytes())
    }

    /// Status snapshot for the UI's transport indicators.
    pub fn status(&self) -> Result<UiStatus, String> {
        let s = self.node.status().map_err(|e| e.to_string())?;
        Ok(UiStatus {
            address: s.address,
            peer: s.peer,
            listen: s.listen,
            lan_peers: s.lan_peers,
            nat: match s.nat {
                NatVerdict::Public => "public",
                NatVerdict::Private => "private",
                NatVerdict::Unknown => "unknown",
            },
            queued: s.queued,
            scheduled: s.scheduled,
            transit: s.transit,
            contacts: s.contacts,
        })
    }

    /// Export a fresh prekey bundle as pasteable hex plus a QR carrying
    /// the same hex (uppercase, so the QR stays in its compact
    /// alphanumeric mode; decoding is case-insensitive everywhere).
    pub fn my_bundle(&self) -> Result<UiBundle, String> {
        let bytes = self.node.handshake_bundle().map_err(|e| e.to_string())?;
        let hex = hex_encode(&bytes);
        let qr_svg = qr::svg(hex.to_uppercase().as_bytes())?;
        Ok(UiBundle { hex, qr_svg })
    }

    /// Add a contact from pasted/scanned bundle hex, with delivery hints.
    /// Returns the new contact's peer id.
    pub fn add_contact(
        &self,
        name: String,
        bundle_hex: &str,
        hints: &[UiHint],
    ) -> Result<String, String> {
        let bundle = hex_decode(bundle_hex).ok_or("bundle must be hex")?;
        let hints = hints
            .iter()
            .map(UiHint::to_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        self.node
            .add_contact(name, bundle, hints)
            .map_err(|e| e.to_string())
    }

    /// Add a contact from their kult address alone (DHT lookup).
    pub fn add_contact_by_address(&self, name: String, address: String) -> Result<String, String> {
        self.node
            .add_contact_by_address(name, address)
            .map_err(|e| e.to_string())
    }

    /// Assess a proposed private local petname without mutation.
    pub fn assess_contact_name(
        &self,
        peer: String,
        name: String,
    ) -> Result<UiContactNameAssessment, String> {
        self.node
            .assess_contact_name(peer, name)
            .map(Into::into)
            .map_err(|e| e.to_string())
    }

    /// Rename one private local petname by exact peer id.
    pub fn rename_contact(
        &self,
        peer: String,
        name: String,
        accept_warnings: bool,
    ) -> Result<UiContactNameAssessment, String> {
        self.node
            .rename_contact(peer, name, accept_warnings)
            .map(Into::into)
            .map_err(|e| e.to_string())
    }

    /// All stored contacts.
    pub fn contacts(&self) -> Result<Vec<UiContact>, String> {
        Ok(self
            .node
            .contacts()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|c| UiContact {
                peer: c.peer,
                name: c.name,
                verified: c.verified,
            })
            .collect())
    }

    /// Message history with a peer.
    pub fn messages(&self, peer: String) -> Result<Vec<UiMessage>, String> {
        Ok(self
            .node
            .messages_with(peer)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| UiMessage {
                id: m.id,
                peer: m.peer,
                outbound: m.direction == Direction::Outbound,
                state: state_str(m.state),
                timestamp: m.timestamp,
                body: m.body,
                content_kind: content_kind_str(m.content_kind),
                expires_at: m.expires_at,
                edited: m.edited,
                edit_revision: m.edit_revision,
                versions: m
                    .versions
                    .into_iter()
                    .map(|version| UiEditVersion {
                        id: version.id,
                        revision: version.revision,
                        timestamp: version.timestamp,
                        body: version.body,
                    })
                    .collect(),
            })
            .collect())
    }

    /// Queue a message; returns its id (progress arrives as events).
    pub fn send(&self, peer: String, body: String) -> Result<String, String> {
        self.node.send(peer, body).map_err(|e| e.to_string())
    }

    /// Queue pairwise text with exact local expiry.
    pub fn send_disappearing(
        &self,
        peer: String,
        body: String,
        lifetime_secs: u64,
    ) -> Result<String, String> {
        self.node
            .send_disappearing(peer, body, lifetime_secs)
            .map_err(|e| e.to_string())
    }

    /// Queue an immutable edit for this identity's exact pairwise Text.
    pub fn edit_message(
        &self,
        peer: String,
        target_author: String,
        target_content_id: String,
        text: String,
    ) -> Result<String, String> {
        self.node
            .edit_message(peer, target_author, target_content_id, text)
            .map_err(|e| e.to_string())
    }

    /// Import a caller-selected path as a pairwise attachment. The complete
    /// object stays behind the path/streaming boundary.
    pub fn send_attachment(
        &self,
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>,
    ) -> Result<String, String> {
        match generate_preview(Path::new(&path), &media_type)? {
            Some(preview) => self
                .node
                .send_attachment_with_preview(
                    peer,
                    path,
                    media_type,
                    filename,
                    preview.path().display().to_string(),
                    "image/jpeg".to_owned(),
                )
                .map_err(|e| e.to_string()),
            None => self
                .node
                .send_attachment(peer, path, media_type, filename)
                .map_err(|e| e.to_string()),
        }
    }

    /// Import a caller-selected path as one encrypt-once group attachment.
    pub fn send_group_attachment(
        &self,
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>,
    ) -> Result<String, String> {
        match generate_preview(Path::new(&path), &media_type)? {
            Some(preview) => self
                .node
                .send_group_attachment_with_preview(
                    group,
                    path,
                    media_type,
                    filename,
                    preview.path().display().to_string(),
                    "image/jpeg".to_owned(),
                )
                .map_err(|e| e.to_string()),
            None => self
                .node
                .send_group_attachment(group, path, media_type, filename)
                .map_err(|e| e.to_string()),
        }
    }

    /// Import a pairwise view-once attachment, including a generated preview when safe.
    pub fn send_view_once_attachment(
        &self,
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        lifetime_secs: u64,
    ) -> Result<String, String> {
        let staged = PrivateTemp::copy_bounded(
            "view-once-attachment",
            Path::new(&path),
            DESKTOP_ATTACHMENT_MAX_BYTES,
        )?;
        let preview = generate_preview(staged.path(), &media_type)?;
        self.node
            .send_view_once_attachment(
                peer,
                staged.path().display().to_string(),
                media_type,
                filename,
                preview
                    .as_ref()
                    .map(|value| value.path().display().to_string()),
                preview.as_ref().map(|_| "image/jpeg".to_owned()),
                lifetime_secs,
            )
            .map_err(|e| e.to_string())
    }

    /// Import a group view-once attachment.
    pub fn send_group_view_once_attachment(
        &self,
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        lifetime_secs: u64,
    ) -> Result<String, String> {
        let staged = PrivateTemp::copy_bounded(
            "view-once-attachment",
            Path::new(&path),
            DESKTOP_ATTACHMENT_MAX_BYTES,
        )?;
        let preview = generate_preview(staged.path(), &media_type)?;
        self.node
            .send_group_view_once_attachment(
                group,
                staged.path().display().to_string(),
                media_type,
                filename,
                preview
                    .as_ref()
                    .map(|value| value.path().display().to_string()),
                preview.as_ref().map(|_| "image/jpeg".to_owned()),
                lifetime_secs,
            )
            .map_err(|e| e.to_string())
    }

    fn image_review(token: String, draft: &PendingImageEdit) -> Result<UiImageReview, String> {
        let bytes = std::fs::read(draft.final_asset.path()).map_err(|error| error.to_string())?;
        if bytes.len() as u64 != draft.info.encoded_bytes {
            return Err("edited image changed after validation".to_owned());
        }
        Ok(UiImageReview {
            token,
            width: draft.info.width,
            height: draft.info.height,
            encoded_bytes: draft.info.encoded_bytes,
            data_url: format!(
                "data:{IMAGE_MEDIA_TYPE};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ),
        })
    }

    /// Stage a caller-selected JPEG/PNG privately, normalize its orientation,
    /// and return an opaque draft with the exact metadata-free initial review.
    pub fn begin_image_edit(&self, path: String) -> Result<UiImageReview, String> {
        let original =
            PrivateTemp::copy_bounded("image-source", Path::new(&path), IMAGE_MAX_INPUT_BYTES)?;
        let final_asset = PrivateTemp::destination("png")?;
        let info = edit_image(
            original.path().display().to_string(),
            final_asset.path().display().to_string(),
            ImageEditRecipe {
                crop: None,
                rotation_quarter_turns: 0,
                regions: vec![],
            },
        )
        .map_err(|error| error.to_string())?;
        let token = format!(
            "{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let draft = PendingImageEdit {
            original,
            final_asset,
            info,
        };
        let review = Self::image_review(token.clone(), &draft)?;
        self.pending_images
            .lock()
            .map_err(|_| "image draft lock failed".to_owned())?
            .insert(token, draft);
        Ok(review)
    }

    /// Re-render one protected draft through the shared Rust contract. The
    /// previous final is retained until the replacement has validated.
    pub fn update_image_edit(
        &self,
        token: String,
        recipe: UiImageEditRecipe,
    ) -> Result<UiImageReview, String> {
        let mut drafts = self
            .pending_images
            .lock()
            .map_err(|_| "image draft lock failed".to_owned())?;
        let draft = drafts
            .get_mut(&token)
            .ok_or_else(|| "image draft expired or was discarded".to_owned())?;
        let replacement = PrivateTemp::destination("png")?;
        let info = edit_image(
            draft.original.path().display().to_string(),
            replacement.path().display().to_string(),
            recipe.into_ffi()?,
        )
        .map_err(|error| error.to_string())?;
        draft.final_asset = replacement;
        draft.info = info;
        Self::image_review(token, draft)
    }

    /// Discard every plaintext path held by an editor draft.
    pub fn discard_image_edit(&self, token: String) -> Result<(), String> {
        self.pending_images
            .lock()
            .map_err(|_| "image draft lock failed".to_owned())?
            .remove(&token);
        Ok(())
    }

    /// Import only the exact reviewed final image after atomically checking
    /// that the authoritative carrier explanation has not changed.
    #[allow(clippy::too_many_arguments)] // reviewed-image token plus explicit send policy
    pub fn send_image_edit(
        &self,
        token: String,
        conversation: String,
        destination: String,
        filename: Option<String>,
        expected_carrier: String,
        view_once: bool,
        lifetime_secs: u64,
    ) -> Result<String, String> {
        let current =
            self.attachment_carrier_explanation(conversation.clone(), destination.clone())?;
        if current != expected_carrier {
            return Err(format!("carrier_changed:{current}"));
        }
        let draft = self
            .pending_images
            .lock()
            .map_err(|_| "image draft lock failed".to_owned())?
            .remove(&token)
            .ok_or_else(|| "image draft expired or was discarded".to_owned())?;
        probe_edited_image(draft.final_asset.path().display().to_string())
            .map_err(|error| error.to_string())?;
        if conversation == "group" && view_once {
            self.node
                .send_group_view_once_attachment(
                    destination,
                    draft.final_asset.path().display().to_string(),
                    IMAGE_MEDIA_TYPE.to_owned(),
                    filename.or_else(|| Some("edited-image.png".to_owned())),
                    None,
                    None,
                    lifetime_secs,
                )
                .map_err(|error| error.to_string())
        } else if conversation == "pairwise" && view_once {
            self.node
                .send_view_once_attachment(
                    destination,
                    draft.final_asset.path().display().to_string(),
                    IMAGE_MEDIA_TYPE.to_owned(),
                    filename.or_else(|| Some("edited-image.png".to_owned())),
                    None,
                    None,
                    lifetime_secs,
                )
                .map_err(|error| error.to_string())
        } else if conversation == "group" {
            self.node
                .send_group_attachment(
                    destination,
                    draft.final_asset.path().display().to_string(),
                    IMAGE_MEDIA_TYPE.to_owned(),
                    filename.or_else(|| Some("edited-image.png".to_owned())),
                )
                .map_err(|error| error.to_string())
        } else if conversation == "pairwise" {
            self.node
                .send_attachment(
                    destination,
                    draft.final_asset.path().display().to_string(),
                    IMAGE_MEDIA_TYPE.to_owned(),
                    filename.or_else(|| Some("edited-image.png".to_owned())),
                )
                .map_err(|error| error.to_string())
        } else {
            Err("unknown attachment conversation".to_owned())
        }
    }

    /// Stage and import one explicitly confirmed non-image file. Image MIME
    /// types are forced through the editor so an original can never enter F3.
    pub fn send_confirmed_attachment(
        &self,
        conversation: String,
        destination: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        expected_carrier: String,
    ) -> Result<String, String> {
        if matches!(media_type.as_str(), "image/jpeg" | "image/png") {
            return Err("JPEG and PNG attachments must pass through the image editor".to_owned());
        }
        let current =
            self.attachment_carrier_explanation(conversation.clone(), destination.clone())?;
        if current != expected_carrier {
            return Err(format!("carrier_changed:{current}"));
        }
        let staged = PrivateTemp::copy_bounded(
            "attachment",
            Path::new(&path),
            DESKTOP_ATTACHMENT_MAX_BYTES,
        )?;
        if conversation == "group" {
            self.node
                .send_group_attachment(
                    destination,
                    staged.path().display().to_string(),
                    media_type,
                    filename,
                )
                .map_err(|error| error.to_string())
        } else if conversation == "pairwise" {
            self.node
                .send_attachment(
                    destination,
                    staged.path().display().to_string(),
                    media_type,
                    filename,
                )
                .map_err(|error| error.to_string())
        } else {
            Err("unknown attachment conversation".to_owned())
        }
    }

    fn canonical_audio(&self, encoded: &str) -> Result<(PrivateTemp, AudioInfo), String> {
        let max_encoded = AUDIO_MAX_BYTES.div_ceil(3) * 4;
        if encoded.len() as u64 > max_encoded {
            return Err("recorded audio exceeds the 60 second limit".to_owned());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "recorded audio is not valid base64".to_owned())?;
        if bytes.len() as u64 > AUDIO_MAX_BYTES {
            return Err("recorded audio exceeds the 60 second limit".to_owned());
        }
        let source = PrivateTemp::with_bytes("native.wav", &bytes)?;
        let canonical = PrivateTemp::destination("wav")?;
        let info = canonicalize_recorded_audio(
            source.path().display().to_string(),
            canonical.path().display().to_string(),
        )
        .map_err(|error| error.to_string())?;
        Ok((canonical, info))
    }

    /// Validate, strip metadata from, and import one explicitly confirmed
    /// pairwise recording through the existing attachment pipeline.
    pub fn send_recorded_audio(&self, peer: String, encoded: String) -> Result<String, String> {
        let (audio, _) = self.canonical_audio(&encoded)?;
        self.node
            .send_attachment(
                peer,
                audio.path().display().to_string(),
                AUDIO_MEDIA_TYPE.to_owned(),
                Some("audio-message.wav".to_owned()),
            )
            .map_err(|error| error.to_string())
    }

    /// Validate, strip metadata from, and import one explicitly confirmed
    /// encrypt-once sender-key group recording.
    pub fn send_group_recorded_audio(
        &self,
        group: String,
        encoded: String,
    ) -> Result<String, String> {
        let (audio, _) = self.canonical_audio(&encoded)?;
        self.node
            .send_group_attachment(
                group,
                audio.path().display().to_string(),
                AUDIO_MEDIA_TYPE.to_owned(),
                Some("audio-message.wav".to_owned()),
            )
            .map_err(|error| error.to_string())
    }

    /// Explain the authoritative current carrier gate at audio confirmation.
    pub fn audio_carrier_explanation(
        &self,
        conversation: String,
        destination: String,
    ) -> Result<String, String> {
        self.carrier_explanation(conversation, destination, "audio")
    }

    /// Explain the authoritative current carrier gate at generic file or
    /// edited-image confirmation.
    pub fn attachment_carrier_explanation(
        &self,
        conversation: String,
        destination: String,
    ) -> Result<String, String> {
        self.carrier_explanation(conversation, destination, "attachment")
    }

    fn carrier_explanation(
        &self,
        conversation: String,
        destination: String,
        subject: &str,
    ) -> Result<String, String> {
        let snapshots = self
            .node
            .carrier_capabilities()
            .map_err(|error| error.to_string())?;
        let members = if conversation == "group" {
            self.node
                .groups()
                .map_err(|error| error.to_string())?
                .into_iter()
                .find(|group| group.id == destination)
                .ok_or_else(|| "unknown group".to_owned())?
                .members
                .into_iter()
                .filter(|peer| peer != &self.node.peer())
                .collect::<Vec<_>>()
        } else {
            vec![destination]
        };
        let mut mesh = 0usize;
        let mut unavailable = 0usize;
        for peer in &members {
            match snapshots
                .iter()
                .find(|snapshot| &snapshot.peer == peer)
                .map(|snapshot| snapshot.capability)
                .unwrap_or(CarrierCapability::OfflineOrUnknown)
            {
                CarrierCapability::Realtime | CarrierCapability::Bulk => {}
                CarrierCapability::MeshOnly => mesh += 1,
                CarrierCapability::OfflineOrUnknown => unavailable += 1,
            }
        }
        Ok(if members.is_empty() {
            format!(
                "This group has no other current recipients; no {subject} delivery will be created."
            )
        } else if mesh > 0 && unavailable > 0 {
            format!(
                "{mesh} recipient{} ha{} only a mesh route, so {subject} waits for a faster link and emits zero manifest, chunk, missing-range, or other bulk mesh frames; {unavailable} more ha{} no fresh route. Recipients with a fresh realtime or bulk link can proceed.",
                if mesh == 1 { "" } else { "s" },
                if mesh == 1 { "s" } else { "ve" },
                if unavailable == 1 { "s" } else { "ve" }
            )
        } else if mesh > 0 {
            format!(
                "Will send when a faster link exists for {mesh} recipient{}. This {subject} emits zero manifest, chunk, missing-range, or other bulk mesh frames.",
                if mesh == 1 { "" } else { "s" }
            )
        } else if unavailable > 0 {
            format!(
                "Will remain queued locally until {} recipient{} ha{} a fresh faster link.",
                unavailable,
                if unavailable == 1 { "" } else { "s" },
                if unavailable == 1 { "s" } else { "ve" }
            )
        } else {
            "Every current recipient has a fresh realtime or bulk link; normal attachment quotas apply."
                .to_owned()
        })
    }

    /// Every supported transfer as render-safe state. No keys, hashes,
    /// chunk paths, missing ranges, frames, or transport addresses cross
    /// into the shell.
    pub fn attachments(&self) -> Result<Vec<UiAttachment>, String> {
        Ok(self
            .node
            .attachments()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiAttachment::from_ffi)
            .collect())
    }

    /// Accept an inbound attachment offer.
    pub fn accept_attachment(&self, transfer: String) -> Result<(), String> {
        self.node
            .accept_attachment(transfer)
            .map_err(|e| e.to_string())
    }

    /// Durably reject an inbound attachment offer.
    pub fn reject_attachment(&self, transfer: String) -> Result<(), String> {
        self.node
            .reject_attachment(transfer)
            .map_err(|e| e.to_string())
    }

    /// Cancel local transfer activity and release unreferenced partial data.
    pub fn cancel_attachment(&self, transfer: String) -> Result<(), String> {
        self.node
            .cancel_attachment(transfer)
            .map_err(|e| e.to_string())
    }

    /// Pause transfer activity while retaining verified progress.
    pub fn pause_attachment(&self, transfer: String) -> Result<(), String> {
        self.node
            .pause_attachment(transfer)
            .map_err(|e| e.to_string())
    }

    /// Resume a paused transfer from its durable verified progress.
    pub fn resume_attachment(&self, transfer: String) -> Result<(), String> {
        self.node
            .resume_attachment(transfer)
            .map_err(|e| e.to_string())
    }

    /// Stream a completed primary object to a protected, new caller-selected
    /// path. Existing destinations are never overwritten.
    pub fn export_attachment(&self, transfer: String, path: String) -> Result<(), String> {
        self.node
            .export_attachment(transfer, path)
            .map_err(|e| e.to_string())
    }

    /// Terminal first-open of view-once media into a protected new path.
    pub fn consume_view_once_attachment(
        &self,
        transfer: String,
        path: String,
    ) -> Result<(), String> {
        self.node
            .consume_view_once_attachment(transfer, path)
            .map_err(|e| e.to_string())
    }

    /// Materialize one completed inbound recognized file into a protected
    /// transient and hand it to the operating system after explicit user
    /// action. Suspicious, mismatched, active, or unknown hints remain
    /// export-only. The transient is retained only for this unlocked session.
    pub fn open_attachment(&self, transfer: String) -> Result<(), String> {
        let attachment = self
            .node
            .attachments()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer)
            .ok_or_else(|| "attachment is unavailable".to_owned())?;
        if attachment.direction != AttachmentDirection::Inbound
            || attachment.state != AttachmentState::Complete
        {
            return Err("only completed inbound attachments can be opened".to_owned());
        }
        let primary = attachment
            .objects
            .into_iter()
            .find(|object| !object.preview)
            .ok_or_else(|| "attachment primary object is unavailable".to_owned())?;
        if primary.presentation.open_policy != FfiAttachmentOpenPolicy::ExternalOpen {
            return Err("attachment policy permits caller-selected export only".to_owned());
        }
        let extension = primary
            .filename
            .as_deref()
            .and_then(|name| Path::new(name).extension())
            .and_then(|value| value.to_str())
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 16
                    && value.as_bytes().iter().all(u8::is_ascii_alphanumeric)
            })
            .unwrap_or("bin");
        let materialized = PrivateTemp::destination(extension)?;
        self.node
            .export_attachment(transfer.clone(), materialized.path().display().to_string())
            .map_err(|error| error.to_string())?;
        open_with_system(materialized.path())?;
        self.opened_attachments
            .lock()
            .map_err(|_| "opened attachment state is unavailable".to_owned())?
            .insert(transfer, materialized);
        Ok(())
    }

    /// Decrypt a completed sealed preview into a short-lived protected file,
    /// read its bounded bytes, delete it, and return a browser-safe data URL.
    pub fn attachment_preview(&self, transfer: String) -> Result<String, String> {
        let media_type = self
            .node
            .attachments()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer)
            .and_then(|attachment| {
                attachment
                    .objects
                    .into_iter()
                    .find(|object| object.preview)
                    .map(|object| object.media_type)
            })
            .ok_or_else(|| "attachment preview is unavailable".to_owned())?;
        if !matches!(media_type.as_str(), "image/jpeg" | "image/png") {
            return Err("attachment preview has an invalid media type".to_owned());
        }
        let preview = PrivateTemp::destination("jpg")?;
        self.node
            .export_attachment_preview(transfer, preview.path().display().to_string())
            .map_err(|e| e.to_string())?;
        let bytes = std::fs::read(preview.path()).map_err(|e| e.to_string())?;
        if bytes.len() > 256 * 1024 {
            return Err("attachment preview exceeds protocol limit".to_owned());
        }
        Ok(format!(
            "data:{media_type};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ))
    }

    /// Decrypt a completed canonical audio object through a protected transient,
    /// validate it, derive duration/waveform locally, and return bounded playback bytes.
    pub fn attachment_audio(&self, transfer: String) -> Result<UiAudioMedia, String> {
        let media_type = self
            .node
            .attachments()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer)
            .and_then(|attachment| {
                attachment
                    .objects
                    .into_iter()
                    .find(|object| !object.preview)
                    .map(|object| object.media_type)
            })
            .ok_or_else(|| "audio attachment is unavailable".to_owned())?;
        if media_type != AUDIO_MEDIA_TYPE {
            return Err("attachment is not canonical recorded audio".to_owned());
        }
        let audio = PrivateTemp::destination("wav")?;
        self.node
            .export_attachment(transfer, audio.path().display().to_string())
            .map_err(|error| error.to_string())?;
        let info = probe_recorded_audio(audio.path().display().to_string())
            .map_err(|error| error.to_string())?;
        let bytes = std::fs::read(audio.path()).map_err(|error| error.to_string())?;
        Ok(UiAudioMedia {
            data_url: format!(
                "data:{AUDIO_MEDIA_TYPE};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ),
            duration_ms: info.duration_ms,
            waveform: info.waveform,
        })
    }

    /// Materialize a completed canonical edited image through a protected
    /// transient, validate it, read the bounded bytes, and immediately delete it.
    pub fn attachment_image(&self, transfer: String) -> Result<String, String> {
        let media_type = self
            .node
            .attachments()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer)
            .and_then(|attachment| {
                attachment
                    .objects
                    .into_iter()
                    .find(|object| !object.preview)
                    .map(|object| object.media_type)
            })
            .ok_or_else(|| "image attachment is unavailable".to_owned())?;
        if media_type != IMAGE_MEDIA_TYPE {
            return Err("attachment is not a canonical edited image".to_owned());
        }
        let image = PrivateTemp::destination("png")?;
        self.node
            .export_attachment(transfer, image.path().display().to_string())
            .map_err(|error| error.to_string())?;
        let info = probe_edited_image(image.path().display().to_string())
            .map_err(|error| error.to_string())?;
        let bytes = std::fs::read(image.path()).map_err(|error| error.to_string())?;
        if bytes.len() as u64 != info.encoded_bytes {
            return Err("canonical edited image changed during preview".to_owned());
        }
        Ok(format!(
            "data:{IMAGE_MEDIA_TYPE};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ))
    }

    /// Schedule pairwise text for an absolute UTC Unix instant.
    pub fn schedule(&self, peer: String, body: String, not_before: u64) -> Result<String, String> {
        self.node
            .schedule(peer, body, not_before)
            .map_err(|e| e.to_string())
    }

    /// Schedule group text for an absolute UTC Unix instant.
    pub fn schedule_group(
        &self,
        group: String,
        body: String,
        not_before: u64,
    ) -> Result<String, String> {
        self.node
            .schedule_group(group, body, not_before)
            .map_err(|e| e.to_string())
    }

    /// Edit one scheduled outbox entry before activation.
    pub fn edit_scheduled(
        &self,
        message: String,
        body: String,
        not_before: u64,
    ) -> Result<(), String> {
        self.node
            .edit_scheduled(message, body, not_before)
            .map_err(|e| e.to_string())
    }

    /// Cancel one scheduled outbox entry before activation.
    pub fn cancel_scheduled(&self, message: String) -> Result<(), String> {
        self.node
            .cancel_scheduled(message)
            .map_err(|e| e.to_string())
    }

    /// Full scheduled outbox for rendering alongside ordinary histories.
    pub fn scheduled_messages(&self) -> Result<Vec<UiScheduledMessage>, String> {
        Ok(self
            .node
            .scheduled_messages()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|message| UiScheduledMessage {
                id: message.id,
                conversation: match message.conversation {
                    ScheduledConversation::Peer => "peer",
                    ScheduledConversation::Group => "group",
                },
                destination: message.destination,
                created_at: message.created_at,
                not_before: message.not_before,
                body: message.body,
                state: "scheduled",
            })
            .collect())
    }

    /// Stable reserved identity for the local note-to-self conversation.
    pub fn note_to_self_id(&self) -> String {
        self.node.note_to_self_id()
    }

    /// Read the private local appearance choice.
    pub fn theme(&self) -> Result<UiThemeInfo, String> {
        let theme = self.node.theme().map_err(|error| error.to_string())?;
        Ok(UiThemeInfo {
            preference: UiThemePreference::from_ffi(theme.preference),
            persisted: theme.persisted,
        })
    }

    /// Idempotently persist one canonical appearance choice.
    pub fn set_theme(&self, preference: UiThemePreference) -> Result<bool, String> {
        self.node
            .set_theme(preference.into_ffi())
            .map_err(|error| error.to_string())
    }

    /// Read one custom icon, or `None` for generated initials fallback.
    pub fn custom_icon(&self, target: UiCustomIconTarget) -> Result<Option<UiCustomIcon>, String> {
        Ok(self
            .node
            .custom_icon(target.to_ffi()?)
            .map_err(|error| error.to_string())?
            .map(UiCustomIcon::from_ffi))
    }

    /// Crop, sanitize, and seal a selected local JPEG/PNG.
    pub fn set_custom_icon_from_path(
        &self,
        target: UiCustomIconTarget,
        path: String,
        crop: Option<UiCustomIconCrop>,
    ) -> Result<UiCustomIcon, String> {
        self.node
            .set_custom_icon_from_path(
                target.to_ffi()?,
                path,
                crop.map(|crop| FfiCustomIconCrop {
                    x: crop.x,
                    y: crop.y,
                    width: crop.width,
                    height: crop.height,
                }),
            )
            .map(UiCustomIcon::from_ffi)
            .map_err(|error| error.to_string())
    }

    /// Render and seal one bundled glyph token.
    pub fn set_bundled_custom_icon(
        &self,
        target: UiCustomIconTarget,
        glyph: String,
    ) -> Result<UiCustomIcon, String> {
        self.node
            .set_bundled_custom_icon(target.to_ffi()?, glyph)
            .map(UiCustomIcon::from_ffi)
            .map_err(|error| error.to_string())
    }

    /// Remove one icon and return to generated initials.
    pub fn clear_custom_icon(&self, target: UiCustomIconTarget) -> Result<bool, String> {
        self.node
            .clear_custom_icon(target.to_ffi()?)
            .map_err(|error| error.to_string())
    }

    /// Read current sealed custom-icon quota usage.
    pub fn custom_icon_usage(&self) -> Result<UiCustomIconUsage, String> {
        let usage = self
            .node
            .custom_icon_quota_usage()
            .map_err(|error| error.to_string())?;
        Ok(UiCustomIconUsage {
            records: usage.records,
            bytes: usage.bytes,
        })
    }

    /// Create one private local folder.
    pub fn create_folder(&self, name: String) -> Result<UiFolder, String> {
        self.node
            .create_folder(name)
            .map(UiFolder::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// List folders in deterministic persisted manual order.
    pub fn folders(&self) -> Result<Vec<UiFolder>, String> {
        Ok(self
            .node
            .folders()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiFolder::from_ffi)
            .collect())
    }

    /// Get one folder by exact technical id.
    pub fn folder(&self, folder: String) -> Result<UiFolder, String> {
        self.node
            .folder(folder)
            .map(UiFolder::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Rename one folder without changing identity, order, or membership.
    pub fn rename_folder(&self, folder: String, name: String) -> Result<UiFolder, String> {
        self.node
            .rename_folder(folder, name)
            .map(UiFolder::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Atomically reorder the complete active folder id set.
    pub fn reorder_folders(&self, folders: Vec<String>) -> Result<Vec<UiFolder>, String> {
        Ok(self
            .node
            .reorder_folders(folders)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiFolder::from_ffi)
            .collect())
    }

    /// Preview assignment count before destructive folder deletion.
    pub fn folder_delete_assignment_count(&self, folder: String) -> Result<u64, String> {
        self.node
            .folder_delete_assignment_count(folder)
            .map_err(|e| e.to_string())
    }

    /// Atomically delete a folder and cascade assignments to Unfiled.
    pub fn delete_folder(&self, folder: String, confirm: bool) -> Result<u64, String> {
        self.node
            .delete_folder(folder, confirm)
            .map_err(|e| e.to_string())
    }

    /// Idempotently move one exact typed conversation into a folder.
    pub fn move_to_folder(&self, folder: String, target: UiFolderTarget) -> Result<bool, String> {
        self.node
            .move_to_folder(folder, target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Idempotently move one exact typed conversation to virtual Unfiled.
    pub fn unfile_conversation(&self, target: UiFolderTarget) -> Result<bool, String> {
        self.node
            .unfile_conversation(target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// List active typed membership for one folder.
    pub fn folder_membership(&self, folder: String) -> Result<Vec<UiFolderConversation>, String> {
        Ok(self
            .node
            .folder_membership(folder)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiFolderConversation::from_ffi)
            .collect())
    }

    /// Return one exact typed conversation's active folder.
    pub fn conversation_folder(&self, target: UiFolderTarget) -> Result<Option<UiFolder>, String> {
        Ok(self
            .node
            .conversation_folder(target.to_ffi()?)
            .map_err(|e| e.to_string())?
            .map(UiFolder::from_ffi))
    }

    /// Classify a folder selection, then independently apply labels.
    pub fn folder_conversations(
        &self,
        selection: UiFolderSelection,
        labels: Vec<String>,
        mode: String,
    ) -> Result<UiFolderConversationResult, String> {
        let mode = match mode.as_str() {
            "any" => FfiLabelMatchMode::Any,
            "all" => FfiLabelMatchMode::All,
            _ => return Err("label filter mode must be any or all".to_owned()),
        };
        self.node
            .folder_conversations(selection.to_ffi()?, labels, mode)
            .map(UiFolderConversationResult::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Render-safe stale local folder-assignment diagnostics.
    pub fn stale_folders(&self) -> Result<Vec<UiStaleFolder>, String> {
        Ok(self
            .node
            .stale_folders()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiStaleFolder::from_ffi)
            .collect())
    }

    /// Remove one exact folder assignment only while it remains stale.
    pub fn cleanup_stale_folder(
        &self,
        folder: String,
        target: UiFolderTarget,
    ) -> Result<bool, String> {
        self.node
            .cleanup_stale_folder(folder, target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Create one private local label.
    pub fn create_label(&self, name: String, color: String) -> Result<UiLabel, String> {
        self.node
            .create_label(name, color)
            .map(UiLabel::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// List labels in stable insertion order.
    pub fn labels(&self) -> Result<Vec<UiLabel>, String> {
        Ok(self
            .node
            .labels()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiLabel::from_ffi)
            .collect())
    }

    /// Get one label by exact technical id.
    pub fn label(&self, label: String) -> Result<UiLabel, String> {
        self.node
            .label(label)
            .map(UiLabel::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Rename/recolor one label without changing identity or membership.
    pub fn update_label(
        &self,
        label: String,
        name: String,
        color: String,
    ) -> Result<UiLabel, String> {
        self.node
            .update_label(label, name, color)
            .map(UiLabel::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Preview the number of memberships removed by a label deletion.
    pub fn label_delete_assignment_count(&self, label: String) -> Result<u64, String> {
        self.node
            .label_delete_assignment_count(label)
            .map_err(|e| e.to_string())
    }

    /// Atomically delete a label and all memberships after explicit confirmation.
    pub fn delete_label(&self, label: String, confirm: bool) -> Result<u64, String> {
        self.node
            .delete_label(label, confirm)
            .map_err(|e| e.to_string())
    }

    /// Idempotently assign a label to an exact typed target.
    pub fn assign_label(&self, label: String, target: UiLabelTarget) -> Result<bool, String> {
        self.node
            .assign_label(label, target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Idempotently unassign a label from an exact typed target.
    pub fn unassign_label(&self, label: String, target: UiLabelTarget) -> Result<bool, String> {
        self.node
            .unassign_label(label, target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// List active membership for one label.
    pub fn label_membership(&self, label: String) -> Result<Vec<UiLabelConversation>, String> {
        Ok(self
            .node
            .label_membership(label)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiLabelConversation::from_ffi)
            .collect())
    }

    /// List active labels for an exact typed conversation.
    pub fn labels_for_conversation(&self, target: UiLabelTarget) -> Result<Vec<UiLabel>, String> {
        Ok(self
            .node
            .labels_for_conversation(target.to_ffi()?)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiLabel::from_ffi)
            .collect())
    }

    /// Render-safe stale local label membership diagnostics.
    pub fn stale_labels(&self) -> Result<Vec<UiStaleLabel>, String> {
        Ok(self
            .node
            .stale_labels()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiStaleLabel::from_ffi)
            .collect())
    }

    /// Remove one exact membership only while it remains stale.
    pub fn cleanup_stale_label(
        &self,
        label: String,
        target: UiLabelTarget,
    ) -> Result<bool, String> {
        self.node
            .cleanup_stale_label(label, target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Filter eligible conversations locally with deterministic any/all semantics.
    pub fn filter_labels(
        &self,
        labels: Vec<String>,
        mode: String,
    ) -> Result<UiLabelFilterResult, String> {
        let mode = match mode.as_str() {
            "any" => FfiLabelMatchMode::Any,
            "all" => FfiLabelMatchMode::All,
            _ => return Err("label filter mode must be any or all".to_owned()),
        };
        self.node
            .filter_labels(labels, mode)
            .map(UiLabelFilterResult::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// Idempotently append one exact available conversation to pin order.
    pub fn pin_conversation(&self, target: UiPinTarget) -> Result<bool, String> {
        self.node
            .pin_conversation(target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Idempotently remove one exact active or stale pin.
    pub fn unpin_conversation(&self, target: UiPinTarget) -> Result<bool, String> {
        self.node
            .unpin_conversation(target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Inspect one exact target's durable pin state.
    pub fn pin_state(&self, target: UiPinTarget) -> Result<Option<UiPin>, String> {
        Ok(self
            .node
            .pin_state(target.to_ffi()?)
            .map_err(|e| e.to_string())?
            .map(UiPin::from_ffi))
    }

    /// List every durable active or stale pin.
    pub fn pins(&self) -> Result<Vec<UiPin>, String> {
        Ok(self
            .node
            .pins()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiPin::from_ffi)
            .collect())
    }

    /// Atomically reorder the exact complete durable pin set.
    pub fn reorder_pins(&self, targets: Vec<UiPinTarget>) -> Result<Vec<UiPin>, String> {
        let targets = targets
            .iter()
            .map(UiPinTarget::to_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .node
            .reorder_pins(targets)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiPin::from_ffi)
            .collect())
    }

    /// List unavailable durable pins.
    pub fn stale_pins(&self) -> Result<Vec<UiPin>, String> {
        Ok(self
            .node
            .stale_pins()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(UiPin::from_ffi)
            .collect())
    }

    /// Remove one exact pin only while unavailable.
    pub fn cleanup_stale_pin(&self, target: UiPinTarget) -> Result<bool, String> {
        self.node
            .cleanup_stale_pin(target.to_ffi()?)
            .map_err(|e| e.to_string())
    }

    /// Compose folder, label, and pin-aware conversation ordering.
    pub fn pin_conversations(
        &self,
        selection: UiFolderSelection,
        labels: Vec<String>,
        mode: String,
    ) -> Result<UiPinConversationResult, String> {
        let mode = match mode.as_str() {
            "any" => FfiLabelMatchMode::Any,
            "all" => FfiLabelMatchMode::All,
            _ => return Err("label filter mode must be any or all".to_owned()),
        };
        self.node
            .pin_conversations(selection.to_ffi()?, labels, mode)
            .map(UiPinConversationResult::from_ffi)
            .map_err(|e| e.to_string())
    }

    /// All sealed local-only note-to-self entries.
    pub fn note_to_self_messages(&self) -> Result<Vec<UiNoteMessage>, String> {
        Ok(self
            .node
            .note_to_self_messages()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|message| UiNoteMessage {
                id: message.id,
                conversation: message.conversation,
                timestamp: message.timestamp,
                body: message.body,
            })
            .collect())
    }

    /// Append one sealed local-only note; no transport work is created.
    pub fn send_note_to_self(&self, body: String) -> Result<String, String> {
        self.node.send_note_to_self(body).map_err(|e| e.to_string())
    }

    /// Create a sender-key group from stored contacts. Returns its id.
    pub fn create_group(&self, name: String, members: Vec<String>) -> Result<String, String> {
        self.node
            .create_group(name, members)
            .map_err(|e| e.to_string())
    }

    /// All locally stored groups, excluding every secret and chain value.
    pub fn groups(&self) -> Result<Vec<UiGroup>, String> {
        Ok(self
            .node
            .groups()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|group| UiGroup {
                id: group.id,
                name: group.name,
                creator: group.creator,
                members: group.members,
            })
            .collect())
    }

    /// Group history with honest per-recipient delivery states.
    pub fn group_messages(&self, group: String) -> Result<Vec<UiGroupMessage>, String> {
        Ok(self
            .node
            .group_messages(group)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|message| UiGroupMessage {
                id: message.id,
                group: message.group,
                sender: message.sender,
                outbound: message.direction == Direction::Outbound,
                timestamp: message.timestamp,
                body: message.body,
                content_kind: content_kind_str(message.content_kind),
                expires_at: message.expires_at,
                mention_spans: message
                    .mention_spans
                    .into_iter()
                    .map(|span| UiMentionSpan {
                        start: span.start,
                        end: span.end,
                        target: span.target,
                    })
                    .collect(),
                edited: message.edited,
                edit_revision: message.edit_revision,
                versions: message
                    .versions
                    .into_iter()
                    .map(|version| UiEditVersion {
                        id: version.id,
                        revision: version.revision,
                        timestamp: version.timestamp,
                        body: version.body,
                    })
                    .collect(),
                deliveries: message
                    .deliveries
                    .into_iter()
                    .map(|delivery| UiGroupDelivery {
                        peer: delivery.peer,
                        state: state_str(delivery.state),
                    })
                    .collect(),
            })
            .collect())
    }

    /// Queue one encrypted group message. Per-member progress arrives as
    /// `GroupDeliveryUpdated` events.
    pub fn send_group(&self, group: String, body: String) -> Result<String, String> {
        self.node.send_group(group, body).map_err(|e| e.to_string())
    }

    /// Queue group text with exact local expiry.
    pub fn send_group_disappearing(
        &self,
        group: String,
        body: String,
        lifetime_secs: u64,
    ) -> Result<String, String> {
        self.node
            .send_group_disappearing(group, body, lifetime_secs)
            .map_err(|e| e.to_string())
    }

    /// Queue an immutable edit for this identity's exact group Text.
    pub fn edit_group_message(
        &self,
        group: String,
        target_author: String,
        target_content_id: String,
        text: String,
    ) -> Result<String, String> {
        self.node
            .edit_group_message(group, target_author, target_content_id, text)
            .map_err(|e| e.to_string())
    }

    /// Current conservative semantic Mention capability verdict.
    pub fn group_mention_capability(&self, group: String) -> Result<UiMentionCapability, String> {
        let capability = self
            .node
            .group_mention_capability(group)
            .map_err(|error| error.to_string())?;
        Ok(UiMentionCapability {
            group: capability.group,
            supported: capability.supported,
            review_token: capability.review_token,
            issues: capability
                .issues
                .into_iter()
                .map(|issue| UiMentionIssue {
                    peer: issue.peer,
                    reason: match issue.reason {
                        MentionCapabilityIssueReason::Unknown => "unknown",
                        MentionCapabilityIssueReason::Unsupported => "unsupported",
                    },
                })
                .collect(),
        })
    }

    /// Send exact fallback text with explicit stable peer Mention spans.
    pub fn send_group_mention(
        &self,
        group: String,
        text: String,
        spans: Vec<UiMentionSpan>,
        review_token: String,
    ) -> Result<String, String> {
        self.node
            .send_group_mention(
                group,
                text,
                spans
                    .into_iter()
                    .map(|span| MentionSpan {
                        start: span.start,
                        end: span.end,
                        target: span.target,
                    })
                    .collect(),
                review_token,
            )
            .map_err(|error| error.to_string())
    }

    /// Create a visible-vote single-choice poll with exact ordered labels.
    pub fn create_group_poll(
        &self,
        group: String,
        question: String,
        options: Vec<String>,
    ) -> Result<String, String> {
        self.node
            .create_group_poll(group, question, options)
            .map_err(|error| error.to_string())
    }

    /// Group poll cards with visible voter heads and locally derived tallies.
    pub fn group_polls(&self, group: String) -> Result<Vec<UiGroupPoll>, String> {
        Ok(self
            .node
            .group_polls(group)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(UiGroupPoll::from_ffi)
            .collect())
    }

    /// Cast or change this identity's choice using stable ids only.
    pub fn vote_group_poll(
        &self,
        group: String,
        poll_author: String,
        poll_id: String,
        option_id: String,
    ) -> Result<String, String> {
        self.node
            .vote_group_poll(group, poll_author, poll_id, option_id)
            .map_err(|error| error.to_string())
    }

    /// Creator-only irreversible final vote-head snapshot.
    pub fn close_group_poll(
        &self,
        group: String,
        poll_author: String,
        poll_id: String,
    ) -> Result<String, String> {
        self.node
            .close_group_poll(group, poll_author, poll_id)
            .map_err(|error| error.to_string())
    }

    /// Add a stored contact to a group (creator only).
    pub fn add_group_member(&self, group: String, peer: String) -> Result<(), String> {
        self.node
            .add_group_member(group, peer)
            .map_err(|e| e.to_string())
    }

    /// Remove a member and rotate the group keys (creator only).
    pub fn remove_group_member(&self, group: String, peer: String) -> Result<(), String> {
        self.node
            .remove_group_member(group, peer)
            .map_err(|e| e.to_string())
    }

    /// Leave a group and drop its live local state; stored history remains.
    pub fn leave_group(&self, group: String) -> Result<(), String> {
        self.node.leave_group(group).map_err(|e| e.to_string())
    }

    /// The safety number with a peer, plus a QR of the raw comparison
    /// value (uppercase hex — both sides render the identical code).
    pub fn safety_number(&self, peer: String) -> Result<UiSafetyNumber, String> {
        let sn = self.node.safety_number(peer).map_err(|e| e.to_string())?;
        let qr_svg = qr::svg(hex_encode(&sn.qr).to_uppercase().as_bytes())?;
        Ok(UiSafetyNumber {
            digits: sn.digits,
            display: sn.display,
            qr_svg,
        })
    }

    /// Record an out-of-band verification.
    pub fn mark_verified(&self, peer: String) -> Result<(), String> {
        self.node.mark_verified(peer).map_err(|e| e.to_string())
    }

    /// Replace a contact's delivery hints.
    pub fn set_hints(&self, peer: String, hints: &[UiHint]) -> Result<(), String> {
        let hints = hints
            .iter()
            .map(UiHint::to_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        self.node.set_hints(peer, hints).map_err(|e| e.to_string())
    }

    /// Publish the prekey bundle on the DHT now.
    pub fn publish(&self) -> Result<(), String> {
        self.node.publish().map_err(|e| e.to_string())
    }

    /// Write an encrypted backup file; returns the one-time 24-word
    /// mnemonic. The shell shows it exactly once and keeps no copy.
    pub fn export_backup(&self, path: String) -> Result<String, String> {
        self.node.export_backup(path).map_err(|e| e.to_string())
    }

    /// Stop the node (idempotent).
    pub fn stop(&self) {
        if let Ok(mut drafts) = self.pending_images.lock() {
            drafts.clear();
        }
        self.node.stop();
        cleanup_media_temps();
    }
}

/// The FFI config for this data dir + settings: `kult-ffi`'s desktop
/// baseline (QUIC + TCP on OS ports, desktop KDF, bridging armed) with the
/// user's network settings on top.
fn build_config(
    data_dir: &Path,
    passphrase: String,
    settings: &NetworkSettings,
    kdf: KdfChoice,
) -> Config {
    let mut config = default_config(data_dir.display().to_string(), passphrase);
    config.kdf = kdf;
    // An emptied-out listen list falls back to the baseline rather than
    // silently starting a node nothing can dial.
    if !settings.listen.is_empty() {
        config.listen = settings.listen.clone();
    }
    config.bootstrap = settings.bootstrap.clone();
    config.relay = settings.relay.clone();
    config.mailboxes = settings.mailboxes.clone();
    config.serve_mailbox = settings.serve_mailbox;
    config.mdns = settings.mdns;
    config.spool = settings.spool.clone();
    config.meshtastic_serial = settings.meshtastic_serial.clone();
    config.meshtastic_tcp = settings.meshtastic_tcp.clone();
    config.bridge = settings.bridge;
    config
}

/// Lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    out
}

/// Hex decoding: case-insensitive, whitespace-tolerant (QR scanners and
/// terminals both like to wrap long strings). `None` on odd length or
/// non-hex input.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()?;
    if digits.len() % 2 != 0 {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| ((pair[0] << 4) | pair[1]) as u8)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_tolerates_noise() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "007fabff");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
        assert_eq!(hex_decode("00 7F\nAB\tff").unwrap(), bytes);
        assert!(hex_decode("007").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn hints_convert_and_reject_garbage() {
        let hint = |kind: &str, value: &str| UiHint {
            kind: kind.to_owned(),
            value: value.to_owned(),
        };
        assert!(matches!(
            hint("multiaddr", "/ip4/1.2.3.4/tcp/1").to_ffi().unwrap(),
            Hint::Multiaddr { .. }
        ));
        assert!(matches!(
            hint("mesh", "broadcast").to_ffi().unwrap(),
            Hint::Mesh { node: u32::MAX }
        ));
        assert!(matches!(
            hint("mesh", "42").to_ffi().unwrap(),
            Hint::Mesh { node: 42 }
        ));
        assert!(hint("mesh", "not-a-number").to_ffi().is_err());
        assert!(hint("teleport", "x").to_ffi().is_err());
        assert!(hint("relay", "  ").to_ffi().is_err());
    }

    #[test]
    fn settings_round_trip_and_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = NetworkSettings::load(dir.path()).unwrap();
        assert!(loaded.mdns && loaded.bridge && loaded.bootstrap.is_empty());

        let mut edited = loaded;
        edited.bootstrap = vec!["/dns4/example.org/udp/4001/quic-v1/p2p/xyz".to_owned()];
        edited.mdns = false;
        edited.save(dir.path()).unwrap();
        let back = NetworkSettings::load(dir.path()).unwrap();
        assert_eq!(back.bootstrap, edited.bootstrap);
        assert!(!back.mdns);

        std::fs::write(dir.path().join("settings.json"), b"{ nope").unwrap();
        assert!(NetworkSettings::load(dir.path())
            .unwrap_err()
            .contains("corrupt"));
    }

    #[test]
    fn events_serialize_with_type_tags() {
        let json = serde_json::to_value(UiEvent::DeliveryUpdated {
            id: "ab".to_owned(),
            state: "delivered",
        })
        .unwrap();
        assert_eq!(json["type"], "delivery_updated");
        assert_eq!(json["state"], "delivered");

        let note = serde_json::to_value(UiEvent::NoteToSelfMessageAdded {
            conversation: "note_to_self".to_owned(),
            id: "05".repeat(16),
            timestamp: 11,
            body: "remember".to_owned(),
        })
        .unwrap();
        assert_eq!(note["type"], "note_to_self_message_added");
        assert_eq!(note["conversation"], "note_to_self");

        let carrier = serde_json::to_value(UiEvent::CarrierCapabilityChanged {
            peer: "04".repeat(32),
            capability: "mesh_only",
            observed_at: 10,
            expires_at: 70,
        })
        .unwrap();
        assert_eq!(carrier["type"], "carrier_capability_changed");
        assert_eq!(carrier["capability"], "mesh_only");
        assert_eq!(carrier["expires_at"], 70);

        let updated = serde_json::to_value(UiEvent::GroupUpdated {
            group: "01".repeat(32),
        })
        .unwrap();
        assert_eq!(updated["type"], "group_updated");

        let received = serde_json::to_value(UiEvent::GroupMessageReceived {
            group: "01".repeat(32),
            sender: "02".repeat(32),
            id: "03".repeat(16),
            timestamp: 7,
            body: "meet at the pass".to_owned(),
            content_kind: "text",
            expires_at: None,
            mention_spans: Vec::new(),
        })
        .unwrap();
        assert_eq!(received["type"], "group_message_received");
        assert_eq!(received["body"], "meet at the pass");

        let mentioned = serde_json::to_value(UiEvent::MentionReceived {
            id: "03".repeat(16),
        })
        .unwrap();
        assert_eq!(mentioned["type"], "mention_received");
        assert!(mentioned.get("body").is_none());

        let delivery = serde_json::to_value(UiEvent::GroupDeliveryUpdated {
            id: "03".repeat(16),
            peer: "02".repeat(32),
            state: "delivered",
        })
        .unwrap();
        assert_eq!(delivery["type"], "group_delivery_updated");
        assert_eq!(delivery["state"], "delivered");

        let attachment = serde_json::to_value(UiEvent::AttachmentUpdated {
            attachment: UiAttachment {
                transfer_id: "04".repeat(16),
                peer: "05".repeat(32),
                conversation: "pairwise",
                group: None,
                direction: "inbound",
                author: "05".repeat(32),
                content_id: "06".repeat(16),
                state: "awaiting_consent",
                view_once: false,
                expires_at: None,
                consumed: false,
                objects: vec![UiAttachmentObject {
                    preview: false,
                    total_bytes: 42,
                    verified_bytes: 0,
                    media_type: "application/octet-stream".to_owned(),
                    filename: Some("notes.bin".to_owned()),
                    presentation: UiAttachmentFilePresentation {
                        kind: "other",
                        open_policy: "export_only",
                        warnings: vec!["unrecognized_type"],
                    },
                    state: "awaiting_consent",
                }],
            },
        })
        .unwrap();
        assert_eq!(attachment["type"], "attachment_updated");
        assert_eq!(attachment["attachment"]["state"], "awaiting_consent");
        assert_eq!(
            attachment["attachment"]["objects"][0]["filename"],
            "notes.bin"
        );
        assert_eq!(content_kind_str(ContentKind::Attachment), "attachment");
    }
}
