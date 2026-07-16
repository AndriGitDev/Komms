//! Sealed local-only organization and presentation records (F5).
//!
//! These records never enter envelopes, DHT records, group state, or transport
//! hints. The SQLite table contains only an insertion-order row id and one
//! independently sealed blob, so copied databases reveal neither record keys
//! nor organization relationships.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Result, Store, StoreError};

const RECORD_MAGIC_V1: &[u8; 4] = b"KLM1";
const RECORD_AD: &[u8] = b"local-metadata";

/// Maximum UTF-8 bytes in a folder name, label name, color token, media type,
/// preference key, or similar local-metadata string.
pub const MAX_LOCAL_METADATA_STRING_BYTES: usize = 256;
/// Maximum number of durable folder definitions.
pub const MAX_FOLDERS: usize = 128;
/// Maximum number of durable conversation-to-folder assignments.
pub const MAX_FOLDER_ASSIGNMENTS: usize = 8_192;
/// Bounded attempts to mint a fresh random folder id before failing closed.
pub const FOLDER_ID_RETRY_LIMIT: usize = 16;
/// Maximum number of durable label definitions.
pub const MAX_LABELS: usize = 128;
/// Maximum number of durable label-to-conversation memberships.
pub const MAX_LABEL_ASSIGNMENTS: usize = 8_192;
/// Maximum number of labels assigned to one conversation.
pub const MAX_LABELS_PER_CONVERSATION: usize = 32;
/// Bounded attempts to mint a fresh random label id before failing closed.
pub const LABEL_ID_RETRY_LIMIT: usize = 16;
/// Maximum number of durable conversation pins.
pub const MAX_PINS: usize = 8_192;
/// Canonical presentation tokens accepted for new label writes.
pub const LABEL_COLORS: [&str; 9] = [
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
];
/// Maximum bytes in a saved message draft (1 MiB).
pub const MAX_DRAFT_BYTES: usize = 1024 * 1024;
/// Maximum bytes in one opaque UI preference value (64 KiB).
pub const MAX_UI_PREFERENCE_VALUE_BYTES: usize = 64 * 1024;
/// Stable sealed preference key shared by every shipped shell for B12.
pub const THEME_PREFERENCE_KEY: &str = "appearance.theme";
/// Canonical theme preference tokens accepted at every public boundary.
pub const THEME_PREFERENCES: [&str; 3] = ["system", "light", "dark"];
/// Cross-shell semantic roles; shells map these to native adaptive colors.
pub const THEME_SEMANTIC_ROLES: [&str; 15] = [
    "background",
    "surface",
    "surface_raised",
    "surface_hover",
    "border",
    "text_primary",
    "text_secondary",
    "accent",
    "on_accent",
    "danger",
    "warning",
    "success",
    "bubble_outgoing",
    "bubble_incoming",
    "focus",
];
/// Maximum bytes in one already-sanitized custom icon (512 KiB).
pub const MAX_CUSTOM_ICON_BYTES: usize = 512 * 1024;

/// Stable identity and type of a conversation in local metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConversationId {
    /// A two-party conversation, keyed by the peer's Ed25519 identity.
    Peer([u8; 32]),
    /// A sender-key group conversation.
    Group([u8; 32]),
    /// The one reserved, device-local note-to-self conversation.
    NoteToSelf,
}

/// Minimal local conversation registry record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationMetadata {
    /// Stable conversation identity, including its type.
    pub conversation: ConversationId,
    /// Unix seconds when this local record was created.
    pub created_at: u64,
}

/// A local conversation folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRecord {
    /// Locally minted stable folder id.
    pub id: [u8; 16],
    /// User-visible folder name.
    pub name: String,
    /// Manual sort position; ties retain insertion order.
    pub order: u32,
}

/// A conversation's single optional folder assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderAssignment {
    /// Conversation being organized.
    pub conversation: ConversationId,
    /// Destination folder id.
    pub folder: [u8; 16],
}

/// Why a durable folder assignment is unavailable to active presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleFolderReason {
    /// The stable folder id has no durable definition.
    MissingFolder,
    /// The exact pairwise/group conversation is not currently available.
    UnavailableConversation,
    /// Both the definition and target are unavailable.
    MissingFolderAndConversation,
}

/// Render-safe diagnostic for one stale durable folder assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleFolderAssignment {
    /// Exact stable folder id; never inferred from presentation.
    pub folder: [u8; 16],
    /// Exact typed conversation target; never inferred from a display name.
    pub conversation: ConversationId,
    /// The unavailable side or sides.
    pub reason: StaleFolderReason,
}

/// One local folder-navigation selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderSelection {
    /// Every available conversation.
    All,
    /// Available conversations with no active assignment.
    Unfiled,
    /// Available conversations assigned to one exact folder id.
    Folder([u8; 16]),
}

/// Result of applying a local folder navigation selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderConversationResult {
    /// Exact selection used for classification.
    pub selection: FolderSelection,
    /// Available conversations in deterministic typed order.
    pub conversations: Vec<ConversationId>,
}

/// An ordered pinned conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    /// Conversation being pinned.
    pub conversation: ConversationId,
    /// Manual pin position; ties fall back to recent activity in the shell.
    pub order: u32,
}

/// One durable pin with its current active/stale status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinStatusRecord {
    /// Exact sealed pin record.
    pub pin: PinRecord,
    /// Whether the exact typed conversation is currently available.
    pub active: bool,
}

/// One available conversation after folder, label, and pin composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinConversationRecord {
    /// Exact stable typed conversation identity.
    pub conversation: ConversationId,
    /// Persisted pin order, or `None` when unpinned.
    pub pin_order: Option<u32>,
    /// Latest ordinary local message activity, or zero with no history.
    pub recent_activity: u64,
}

/// Result of folder-first, label-second, pin-order-last composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinConversationResult {
    /// Exact folder selection used for eligibility.
    pub selection: FolderSelection,
    /// Available selected labels after canonical validation.
    pub selected_labels: Vec<[u8; 16]>,
    /// Requested selected labels whose definitions are unavailable.
    pub unavailable_labels: Vec<[u8; 16]>,
    /// Eligible conversations with one leading pinned block.
    pub conversations: Vec<PinConversationRecord>,
}

/// A private local label definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelRecord {
    /// Locally minted stable label id.
    pub id: [u8; 16],
    /// User-visible label name.
    pub name: String,
    /// Shell-defined semantic color token, not a security signal.
    pub color: String,
}

/// One label-to-conversation membership; multiple labels may target one
/// conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelAssignment {
    /// Label being applied.
    pub label: [u8; 16],
    /// Conversation receiving the label.
    pub conversation: ConversationId,
}

/// Match semantics for a local multi-label conversation filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelFilterMode {
    /// Keep a conversation carrying at least one selected label.
    Any,
    /// Keep a conversation carrying every selected label.
    All,
}

/// Why a durable label assignment is unavailable to active presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleLabelReason {
    /// The stable label id has no durable definition.
    MissingLabel,
    /// The exact pairwise/group conversation is not currently available.
    UnavailableConversation,
    /// Both the definition and target are unavailable.
    MissingLabelAndConversation,
}

/// Render-safe diagnostic for one stale durable membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleLabelAssignment {
    /// Exact stable label id; never inferred from presentation.
    pub label: [u8; 16],
    /// Exact typed conversation target; never inferred from a display name.
    pub conversation: ConversationId,
    /// The unavailable side or sides.
    pub reason: StaleLabelReason,
}

/// Result of applying a bounded local label filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelFilterResult {
    /// Canonically deduplicated, available selected ids in caller order.
    pub selected: Vec<[u8; 16]>,
    /// Selected ids with no current durable definition, in caller order.
    pub unavailable_selected: Vec<[u8; 16]>,
    /// Eligible typed conversations matching the active selection.
    pub conversations: Vec<ConversationId>,
}

/// Validate a new label name without rewriting any byte.
///
/// Only the fixed Unicode Pattern_White_Space scalar set is considered for
/// the all-whitespace rejection. Other Unicode whitespace remains ordinary,
/// exact user data.
pub fn valid_label_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LOCAL_METADATA_STRING_BYTES
        && !name.chars().all(is_pattern_white_space)
}

/// Validate a folder name without rewriting any byte.
pub fn valid_folder_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LOCAL_METADATA_STRING_BYTES
        && !name.chars().all(is_pattern_white_space)
}

/// Return whether a token is canonical for a new label write.
pub fn valid_label_color(color: &str) -> bool {
    LABEL_COLORS.contains(&color)
}

/// Return a safe canonical presentation token for stored data.
///
/// Unknown legacy tokens are retained in their sealed record and backup, but
/// are never evaluated as platform code and render as `neutral`.
pub fn render_label_color(color: &str) -> &'static str {
    LABEL_COLORS
        .iter()
        .copied()
        .find(|known| *known == color)
        .unwrap_or("neutral")
}

fn is_pattern_white_space(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'
            ..='\u{000d}'
                | '\u{0020}'
                | '\u{0085}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
    )
}

/// A sealed local composition draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftRecord {
    /// Conversation where the draft belongs.
    pub conversation: ConversationId,
    /// Opaque composer bytes, interpreted and bounded by the shell/content layer.
    pub content: Vec<u8>,
    /// Unix seconds of the latest edit, for conflict-free local replacement.
    pub updated_at: u64,
}

/// One namespaced, opaque shell preference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPreferenceRecord {
    /// Stable namespaced key shared by the shells where applicable.
    pub key: String,
    /// Opaque value bytes owned by the shell or shared UI contract.
    pub value: Vec<u8>,
}

/// The shared B12 appearance choice. Resolution of `System` remains native
/// to each shell so live platform changes do not require a node mutation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemePreference {
    /// Follow the current operating-system appearance.
    #[default]
    System,
    /// Always use the light semantic palette.
    Light,
    /// Always use the dark semantic palette.
    Dark,
}

impl ThemePreference {
    /// Return the canonical lowercase token persisted and exposed by RPC/FFI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// Parse one exact canonical token.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

/// A local entity that can carry a custom icon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomIconTarget {
    /// A contact, keyed by Ed25519 identity.
    Contact([u8; 32]),
    /// A sender-key group.
    Group([u8; 32]),
    /// A local folder.
    Folder([u8; 16]),
    /// The reserved note-to-self conversation.
    NoteToSelf,
}

/// An already-cropped, metadata-stripped, locally encoded custom icon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomIconRecord {
    /// Entity receiving the icon.
    pub target: CustomIconTarget,
    /// Local encoded media type, such as `image/png`.
    pub media_type: String,
    /// Sanitized encoded image bytes.
    pub bytes: Vec<u8>,
}

/// One sealed F5 record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalMetadataRecord {
    /// Conversation identity/type registry entry.
    Conversation(ConversationMetadata),
    /// Folder definition.
    Folder(FolderRecord),
    /// Single-folder membership for a conversation.
    FolderAssignment(FolderAssignment),
    /// Pinned conversation.
    Pin(PinRecord),
    /// Label definition.
    Label(LabelRecord),
    /// Many-to-many label membership.
    LabelAssignment(LabelAssignment),
    /// Composer draft.
    Draft(DraftRecord),
    /// UI preference.
    UiPreference(UiPreferenceRecord),
    /// Custom local icon.
    CustomIcon(CustomIconRecord),
}

/// Stable logical key used for lookup, replacement, and deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalMetadataKey {
    /// Conversation registry key.
    Conversation(ConversationId),
    /// Folder definition key.
    Folder([u8; 16]),
    /// Folder membership key; one value per conversation enforces one folder.
    FolderAssignment(ConversationId),
    /// Pin key; one value per conversation.
    Pin(ConversationId),
    /// Label definition key.
    Label([u8; 16]),
    /// Label membership key; multiple distinct labels may target a conversation.
    LabelAssignment([u8; 16], ConversationId),
    /// Draft key; one value per conversation.
    Draft(ConversationId),
    /// Namespaced UI preference key.
    UiPreference(String),
    /// Custom icon target key; one icon per target.
    CustomIcon(CustomIconTarget),
}

impl LocalMetadataRecord {
    /// Return the logical key that uniquely identifies this record.
    pub fn key(&self) -> LocalMetadataKey {
        match self {
            Self::Conversation(record) => {
                LocalMetadataKey::Conversation(record.conversation.clone())
            }
            Self::Folder(record) => LocalMetadataKey::Folder(record.id),
            Self::FolderAssignment(record) => {
                LocalMetadataKey::FolderAssignment(record.conversation.clone())
            }
            Self::Pin(record) => LocalMetadataKey::Pin(record.conversation.clone()),
            Self::Label(record) => LocalMetadataKey::Label(record.id),
            Self::LabelAssignment(record) => {
                LocalMetadataKey::LabelAssignment(record.label, record.conversation.clone())
            }
            Self::Draft(record) => LocalMetadataKey::Draft(record.conversation.clone()),
            Self::UiPreference(record) => LocalMetadataKey::UiPreference(record.key.clone()),
            Self::CustomIcon(record) => LocalMetadataKey::CustomIcon(record.target.clone()),
        }
    }

    fn validate(&self) -> Result<()> {
        let string_ok =
            |value: &str| !value.is_empty() && value.len() <= MAX_LOCAL_METADATA_STRING_BYTES;
        let valid = match self {
            Self::Conversation(_) | Self::FolderAssignment(_) | Self::Pin(_) => true,
            Self::Folder(record) => valid_folder_name(&record.name),
            Self::Label(record) => string_ok(&record.name) && string_ok(&record.color),
            Self::LabelAssignment(_) => true,
            Self::Draft(record) => record.content.len() <= MAX_DRAFT_BYTES,
            Self::UiPreference(record) => {
                string_ok(&record.key) && record.value.len() <= MAX_UI_PREFERENCE_VALUE_BYTES
            }
            Self::CustomIcon(record) => {
                string_ok(&record.media_type)
                    && !record.bytes.is_empty()
                    && record.bytes.len() <= MAX_CUSTOM_ICON_BYTES
            }
        };
        if valid {
            Ok(())
        } else {
            Err(StoreError::LocalMetadataBounds)
        }
    }
}

impl Store {
    /// Read the canonical sealed theme preference.
    ///
    /// Missing and unknown legacy values both return `None`; callers render
    /// the safe System default without rewriting user data during a read.
    pub fn theme_preference(&self) -> Result<Option<ThemePreference>> {
        let Some(LocalMetadataRecord::UiPreference(record)) = self.get_local_metadata(
            &LocalMetadataKey::UiPreference(THEME_PREFERENCE_KEY.to_owned()),
        )?
        else {
            return Ok(None);
        };
        Ok(std::str::from_utf8(&record.value)
            .ok()
            .and_then(ThemePreference::parse))
    }

    /// Persist one canonical theme preference, returning whether it changed.
    pub fn set_theme_preference(
        &self,
        preference: ThemePreference,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        if self.theme_preference()? == Some(preference) {
            return Ok(false);
        }
        self.put_local_metadata(
            &LocalMetadataRecord::UiPreference(UiPreferenceRecord {
                key: THEME_PREFERENCE_KEY.to_owned(),
                value: preference.as_str().as_bytes().to_vec(),
            }),
            rng,
        )?;
        Ok(true)
    }

    /// Insert or replace one independently sealed local metadata record.
    pub fn put_local_metadata(
        &self,
        record: &LocalMetadataRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        let key = record.key();
        let existing = self
            .local_metadata_rows()?
            .into_iter()
            .find_map(|(rowid, stored)| (stored.key() == key).then_some(rowid));
        let sealed = self.seal_local_metadata(record, rng)?;
        if let Some(rowid) = existing {
            self.conn.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO local_metadata (blob) VALUES (?1)",
                params![sealed],
            )?;
        }
        Ok(())
    }

    /// Read one local metadata record by its stable logical key.
    pub fn get_local_metadata(
        &self,
        key: &LocalMetadataKey,
    ) -> Result<Option<LocalMetadataRecord>> {
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .find_map(|(_, record)| (&record.key() == key).then_some(record)))
    }

    /// Read every local metadata record in stable insertion order.
    pub fn local_metadata(&self) -> Result<Vec<LocalMetadataRecord>> {
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }

    /// Delete one local metadata record. Returns whether it existed.
    pub fn delete_local_metadata(&self, key: &LocalMetadataKey) -> Result<bool> {
        let rowid = self
            .local_metadata_rows()?
            .into_iter()
            .find_map(|(rowid, record)| (&record.key() == key).then_some(rowid));
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        Ok(self.conn.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![rowid],
        )? == 1)
    }

    /// Create a folder with a cryptographically random stable id.
    ///
    /// Duplicate exact names are allowed. Creation appends after the current
    /// active presentation order; when a legacy `u32::MAX` order prevents a
    /// direct append, existing folders are compacted atomically first.
    pub fn create_folder(&self, name: &str, rng: &mut impl CryptoRngCore) -> Result<FolderRecord> {
        validate_new_folder(name)?;
        let rows = self.local_metadata_rows()?;
        let mut existing = rows
            .iter()
            .filter_map(|(rowid, record)| match record {
                LocalMetadataRecord::Folder(folder) => Some((*rowid, folder.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        if existing.len() >= MAX_FOLDERS {
            return Err(StoreError::FolderLimit);
        }
        let ids = existing
            .iter()
            .map(|(_, folder)| folder.id)
            .collect::<HashSet<_>>();
        let id = (0..FOLDER_ID_RETRY_LIMIT)
            .find_map(|_| {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (!ids.contains(&id)).then_some(id)
            })
            .ok_or(StoreError::FolderIdCollision)?;

        existing.sort_by_key(|(rowid, folder)| (folder.order, *rowid, folder.id));
        let compact = existing
            .last()
            .is_some_and(|(_, folder)| folder.order == u32::MAX);
        let order = if compact {
            u32::try_from(existing.len()).map_err(|_| StoreError::FolderLimit)?
        } else {
            existing
                .last()
                .map_or(0, |(_, folder)| folder.order.saturating_add(1))
        };
        let folder = FolderRecord {
            id,
            name: name.to_owned(),
            order,
        };

        let mut updates = Vec::new();
        if compact {
            for (position, (rowid, mut record)) in existing.into_iter().enumerate() {
                record.order = u32::try_from(position).map_err(|_| StoreError::FolderLimit)?;
                let sealed = self.seal_local_metadata(&LocalMetadataRecord::Folder(record), rng)?;
                updates.push((rowid, sealed));
            }
        }
        let sealed = self.seal_local_metadata(&LocalMetadataRecord::Folder(folder.clone()), rng)?;
        let tx = self.conn.unchecked_transaction()?;
        for (rowid, sealed) in updates {
            tx.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        }
        tx.execute(
            "INSERT INTO local_metadata (blob) VALUES (?1)",
            params![sealed],
        )?;
        tx.commit()?;
        Ok(folder)
    }

    /// Read active folder definitions in deterministic presentation order.
    ///
    /// Persisted manual order is primary, durable insertion order is the first
    /// technical tie-breaker, and stable id is the final technical tie-breaker.
    pub fn folders(&self) -> Result<Vec<FolderRecord>> {
        let mut folders = self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(rowid, record)| match record {
                LocalMetadataRecord::Folder(folder) => Some((rowid, folder)),
                _ => None,
            })
            .collect::<Vec<_>>();
        folders.sort_by_key(|(rowid, folder)| (folder.order, *rowid, folder.id));
        Ok(folders.into_iter().map(|(_, folder)| folder).collect())
    }

    /// Read one folder definition by its exact stable id.
    pub fn folder(&self, id: &[u8; 16]) -> Result<Option<FolderRecord>> {
        Ok(self
            .get_local_metadata(&LocalMetadataKey::Folder(*id))?
            .and_then(|record| match record {
                LocalMetadataRecord::Folder(folder) => Some(folder),
                _ => None,
            }))
    }

    /// Atomically rename a folder while preserving id, order, and membership.
    pub fn rename_folder(
        &self,
        id: &[u8; 16],
        name: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FolderRecord> {
        validate_new_folder(name)?;
        let (rowid, mut folder) = self
            .local_metadata_rows()?
            .into_iter()
            .find_map(|(rowid, record)| match record {
                LocalMetadataRecord::Folder(folder) if folder.id == *id => Some((rowid, folder)),
                _ => None,
            })
            .ok_or(StoreError::UnknownFolder)?;
        folder.name = name.to_owned();
        let sealed = self.seal_local_metadata(&LocalMetadataRecord::Folder(folder.clone()), rng)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
            params![rowid, sealed],
        )?;
        tx.commit()?;
        Ok(folder)
    }

    /// Atomically rewrite manual order from the complete active folder id set.
    pub fn reorder_folders(
        &self,
        ordered: &[[u8; 16]],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<FolderRecord>> {
        if ordered.len() > MAX_FOLDERS {
            return Err(StoreError::InvalidFolderOrder);
        }
        let rows = self.local_metadata_rows()?;
        let existing = rows
            .iter()
            .filter_map(|(rowid, record)| match record {
                LocalMetadataRecord::Folder(folder) => Some((folder.id, (*rowid, folder.clone()))),
                _ => None,
            })
            .collect::<std::collections::HashMap<_, _>>();
        let unique = ordered.iter().copied().collect::<HashSet<_>>();
        if ordered.len() != existing.len()
            || unique.len() != ordered.len()
            || unique.iter().any(|id| !existing.contains_key(id))
        {
            return Err(StoreError::InvalidFolderOrder);
        }
        let mut reordered = Vec::with_capacity(ordered.len());
        let mut updates = Vec::with_capacity(ordered.len());
        for (position, id) in ordered.iter().enumerate() {
            let (rowid, mut folder) = existing
                .get(id)
                .cloned()
                .ok_or(StoreError::InvalidFolderOrder)?;
            folder.order = u32::try_from(position).map_err(|_| StoreError::InvalidFolderOrder)?;
            let sealed =
                self.seal_local_metadata(&LocalMetadataRecord::Folder(folder.clone()), rng)?;
            updates.push((rowid, sealed));
            reordered.push(folder);
        }
        let tx = self.conn.unchecked_transaction()?;
        for (rowid, sealed) in updates {
            tx.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        }
        tx.commit()?;
        Ok(reordered)
    }

    /// Count every durable assignment for a folder, including stale targets.
    pub fn folder_assignment_count(&self, id: &[u8; 16]) -> Result<usize> {
        if self.folder(id)?.is_none() {
            return Err(StoreError::UnknownFolder);
        }
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .filter(|(_, record)| {
                matches!(record, LocalMetadataRecord::FolderAssignment(assignment) if assignment.folder == *id)
            })
            .count())
    }

    /// Atomically delete a folder and every assignment that points to it.
    pub fn delete_folder(&self, id: &[u8; 16]) -> Result<usize> {
        let rows = self.local_metadata_rows()?;
        let mut folder_row = None;
        let mut assignment_rows = Vec::new();
        for (rowid, record) in rows {
            match record {
                LocalMetadataRecord::Folder(folder) if folder.id == *id => folder_row = Some(rowid),
                LocalMetadataRecord::FolderAssignment(assignment) if assignment.folder == *id => {
                    assignment_rows.push(rowid)
                }
                _ => {}
            }
        }
        let folder_row = folder_row.ok_or(StoreError::UnknownFolder)?;
        let count = assignment_rows.len();
        let tx = self.conn.unchecked_transaction()?;
        for rowid in assignment_rows {
            tx.execute(
                "DELETE FROM local_metadata WHERE rowid_ = ?1",
                params![rowid],
            )?;
        }
        tx.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![folder_row],
        )?;
        tx.commit()?;
        Ok(count)
    }

    /// Atomically move one available typed conversation into a folder.
    ///
    /// The conversation-keyed F5 record makes replacement single-membership
    /// by construction. Repeating the same destination is an honest no-op.
    pub fn move_conversation_to_folder(
        &self,
        conversation: &ConversationId,
        folder: &[u8; 16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let rows = self.local_metadata_rows()?;
        if !rows.iter().any(
            |(_, record)| matches!(record, LocalMetadataRecord::Folder(item) if item.id == *folder),
        ) {
            return Err(StoreError::UnknownFolder);
        }
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        let existing = rows.iter().find_map(|(rowid, record)| match record {
            LocalMetadataRecord::FolderAssignment(assignment)
                if assignment.conversation == *conversation =>
            {
                Some((*rowid, assignment.folder))
            }
            _ => None,
        });
        if existing.is_some_and(|(_, current)| current == *folder) {
            return Ok(false);
        }
        if existing.is_none()
            && rows
                .iter()
                .filter(|(_, record)| matches!(record, LocalMetadataRecord::FolderAssignment(_)))
                .count()
                >= MAX_FOLDER_ASSIGNMENTS
        {
            return Err(StoreError::FolderAssignmentLimit);
        }
        let record = LocalMetadataRecord::FolderAssignment(FolderAssignment {
            conversation: conversation.clone(),
            folder: *folder,
        });
        let sealed = self.seal_local_metadata(&record, rng)?;
        let tx = self.conn.unchecked_transaction()?;
        if let Some((rowid, _)) = existing {
            tx.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        } else {
            tx.execute(
                "INSERT INTO local_metadata (blob) VALUES (?1)",
                params![sealed],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Atomically move an available typed conversation to virtual Unfiled.
    pub fn unfile_conversation(&self, conversation: &ConversationId) -> Result<bool> {
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        self.remove_folder_assignment(conversation)
    }

    /// Return the active folder for one available conversation.
    ///
    /// A missing folder definition is presented as Unfiled without mutating
    /// the durable stale assignment.
    pub fn folder_for_conversation(
        &self,
        conversation: &ConversationId,
    ) -> Result<Option<FolderRecord>> {
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        let assignment = self
            .get_local_metadata(&LocalMetadataKey::FolderAssignment(conversation.clone()))?
            .and_then(|record| match record {
                LocalMetadataRecord::FolderAssignment(assignment) => Some(assignment),
                _ => None,
            });
        match assignment {
            Some(assignment) => self.folder(&assignment.folder),
            None => Ok(None),
        }
    }

    /// Active available typed membership for one folder.
    pub fn folder_members(&self, folder: &[u8; 16]) -> Result<Vec<ConversationId>> {
        if self.folder(folder)?.is_none() {
            return Err(StoreError::UnknownFolder);
        }
        let assigned = self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::FolderAssignment(assignment)
                    if assignment.folder == *folder =>
                {
                    Some(assignment.conversation)
                }
                _ => None,
            })
            .collect::<HashSet<_>>();
        Ok(self
            .eligible_conversations()?
            .into_iter()
            .filter(|conversation| assigned.contains(conversation))
            .collect())
    }

    /// Classify active conversations as All, Unfiled, or one exact folder.
    pub fn folder_conversations(
        &self,
        selection: FolderSelection,
    ) -> Result<FolderConversationResult> {
        if let FolderSelection::Folder(folder) = selection {
            if self.folder(&folder)?.is_none() {
                return Err(StoreError::UnknownFolder);
            }
        }
        let definitions = self
            .folders()?
            .into_iter()
            .map(|folder| folder.id)
            .collect::<HashSet<_>>();
        let assignments = self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::FolderAssignment(assignment) => {
                    Some((assignment.conversation, assignment.folder))
                }
                _ => None,
            })
            .collect::<std::collections::HashMap<_, _>>();
        let conversations = self
            .eligible_conversations()?
            .into_iter()
            .filter(|conversation| match selection {
                FolderSelection::All => true,
                FolderSelection::Unfiled => assignments
                    .get(conversation)
                    .is_none_or(|folder| !definitions.contains(folder)),
                FolderSelection::Folder(folder) => assignments
                    .get(conversation)
                    .is_some_and(|id| *id == folder),
            })
            .collect();
        Ok(FolderConversationResult {
            selection,
            conversations,
        })
    }

    /// Report stale durable folder assignments without sealed row material.
    pub fn stale_folder_assignments(&self) -> Result<Vec<StaleFolderAssignment>> {
        let rows = self.local_metadata_rows()?;
        let folders = rows
            .iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Folder(folder) => Some(folder.id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let available = self.available_conversations()?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::FolderAssignment(assignment) => {
                    let folder_exists = folders.contains(&assignment.folder);
                    let target_exists = available.contains(&assignment.conversation);
                    let reason = match (folder_exists, target_exists) {
                        (true, true) => return None,
                        (false, true) => StaleFolderReason::MissingFolder,
                        (true, false) => StaleFolderReason::UnavailableConversation,
                        (false, false) => StaleFolderReason::MissingFolderAndConversation,
                    };
                    Some(StaleFolderAssignment {
                        folder: assignment.folder,
                        conversation: assignment.conversation,
                        reason,
                    })
                }
                _ => None,
            })
            .collect())
    }

    /// Remove one exact folder assignment only while it remains stale.
    pub fn cleanup_stale_folder_assignment(
        &self,
        folder: &[u8; 16],
        conversation: &ConversationId,
    ) -> Result<bool> {
        let stale = self
            .stale_folder_assignments()?
            .into_iter()
            .any(|record| record.folder == *folder && record.conversation == *conversation);
        if !stale {
            return Err(StoreError::FolderAssignmentActive);
        }
        self.remove_folder_assignment(conversation)
    }

    fn remove_folder_assignment(&self, conversation: &ConversationId) -> Result<bool> {
        let rowid =
            self.local_metadata_rows()?
                .into_iter()
                .find_map(|(rowid, record)| match record {
                    LocalMetadataRecord::FolderAssignment(assignment)
                        if assignment.conversation == *conversation =>
                    {
                        Some(rowid)
                    }
                    _ => None,
                });
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![rowid],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Idempotently pin one exact available typed conversation.
    ///
    /// New pins append after the complete durable pin order. If a legacy
    /// `u32::MAX` prevents appending, every durable pin (including stale pins)
    /// is compacted in the same transaction before insertion.
    pub fn pin_conversation(
        &self,
        conversation: &ConversationId,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let rows = self.local_metadata_rows()?;
        let mut pins = rows
            .iter()
            .filter_map(|(rowid, record)| match record {
                LocalMetadataRecord::Pin(pin) => Some((*rowid, pin.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        if pins
            .iter()
            .any(|(_, pin)| pin.conversation == *conversation)
        {
            return Ok(false);
        }
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        if pins.len() >= MAX_PINS {
            return Err(StoreError::PinLimit);
        }

        let activity = self.conversation_activity()?;
        pins.sort_by(|left, right| compare_pins(&left.1, &right.1, &activity));
        let compact = pins.last().is_some_and(|(_, pin)| pin.order == u32::MAX);
        let order = if compact {
            u32::try_from(pins.len()).map_err(|_| StoreError::PinLimit)?
        } else {
            pins.last().map_or(0, |(_, pin)| pin.order + 1)
        };

        let mut updates = Vec::new();
        if compact {
            for (position, (rowid, mut pin)) in pins.into_iter().enumerate() {
                pin.order = u32::try_from(position).map_err(|_| StoreError::PinLimit)?;
                let sealed = self.seal_local_metadata(&LocalMetadataRecord::Pin(pin), rng)?;
                updates.push((rowid, sealed));
            }
        }
        let record = PinRecord {
            conversation: conversation.clone(),
            order,
        };
        let sealed = self.seal_local_metadata(&LocalMetadataRecord::Pin(record), rng)?;
        let tx = self.conn.unchecked_transaction()?;
        for (rowid, sealed) in updates {
            tx.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        }
        tx.execute(
            "INSERT INTO local_metadata (blob) VALUES (?1)",
            params![sealed],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Idempotently remove one exact durable pin, active or stale.
    pub fn unpin_conversation(&self, conversation: &ConversationId) -> Result<bool> {
        self.remove_pin(conversation)
    }

    /// Return one exact durable pin with current active/stale status.
    pub fn pin_state(&self, conversation: &ConversationId) -> Result<Option<PinStatusRecord>> {
        let pin = self
            .get_local_metadata(&LocalMetadataKey::Pin(conversation.clone()))?
            .and_then(|record| match record {
                LocalMetadataRecord::Pin(pin) => Some(pin),
                _ => None,
            });
        pin.map(|pin| {
            Ok(PinStatusRecord {
                active: self.conversation_available(&pin.conversation)?,
                pin,
            })
        })
        .transpose()
    }

    /// List every durable pin in deterministic manual/activity/typed order.
    pub fn pins(&self) -> Result<Vec<PinStatusRecord>> {
        let activity = self.conversation_activity()?;
        let available = self.available_conversations()?;
        let mut pins = self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Pin(pin) => Some(pin),
                _ => None,
            })
            .collect::<Vec<_>>();
        pins.sort_by(|left, right| compare_pins(left, right, &activity));
        Ok(pins
            .into_iter()
            .map(|pin| PinStatusRecord {
                active: available.contains(&pin.conversation),
                pin,
            })
            .collect())
    }

    /// Atomically reorder the explicit complete durable pin target set.
    pub fn reorder_pins(
        &self,
        ordered: &[ConversationId],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<PinStatusRecord>> {
        let rows = self.local_metadata_rows()?;
        let current = rows
            .iter()
            .filter_map(|(rowid, record)| match record {
                LocalMetadataRecord::Pin(pin) => {
                    Some((pin.conversation.clone(), (*rowid, pin.clone())))
                }
                _ => None,
            })
            .collect::<HashMap<_, _>>();
        let requested = ordered.iter().cloned().collect::<HashSet<_>>();
        if requested.len() != ordered.len()
            || requested.len() != current.len()
            || requested.iter().any(|target| !current.contains_key(target))
        {
            return Err(StoreError::InvalidPinOrder);
        }
        let mut updates = Vec::with_capacity(ordered.len());
        for (position, conversation) in ordered.iter().enumerate() {
            let (rowid, mut pin) = current
                .get(conversation)
                .cloned()
                .ok_or(StoreError::InvalidPinOrder)?;
            pin.order = u32::try_from(position).map_err(|_| StoreError::PinLimit)?;
            let sealed = self.seal_local_metadata(&LocalMetadataRecord::Pin(pin), rng)?;
            updates.push((rowid, sealed));
        }
        let tx = self.conn.unchecked_transaction()?;
        for (rowid, sealed) in updates {
            tx.execute(
                "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        }
        tx.commit()?;
        self.pins()
    }

    /// List only unavailable durable pins in deterministic durable order.
    pub fn stale_pins(&self) -> Result<Vec<PinRecord>> {
        Ok(self
            .pins()?
            .into_iter()
            .filter_map(|status| (!status.active).then_some(status.pin))
            .collect())
    }

    /// Remove one exact pin only while its target remains unavailable.
    pub fn cleanup_stale_pin(&self, conversation: &ConversationId) -> Result<bool> {
        let Some(status) = self.pin_state(conversation)? else {
            return Err(StoreError::PinActive);
        };
        if status.active {
            return Err(StoreError::PinActive);
        }
        self.remove_pin(conversation)
    }

    /// Apply folder classification, label filtering, then pin-aware ordering.
    pub fn pin_conversations(
        &self,
        selection: FolderSelection,
        selected_labels: &[[u8; 16]],
        label_mode: LabelFilterMode,
    ) -> Result<PinConversationResult> {
        let folders = self.folder_conversations(selection)?;
        let labels = self.filter_label_conversations(selected_labels, label_mode)?;
        let label_eligible = labels.conversations.into_iter().collect::<HashSet<_>>();
        let eligible = folders
            .conversations
            .into_iter()
            .filter(|conversation| label_eligible.contains(conversation))
            .collect::<HashSet<_>>();
        let pin_orders = self
            .pins()?
            .into_iter()
            .filter(|status| status.active)
            .map(|status| (status.pin.conversation, status.pin.order))
            .collect::<HashMap<_, _>>();
        let activity = self.conversation_activity()?;
        let mut conversations = eligible
            .into_iter()
            .map(|conversation| PinConversationRecord {
                pin_order: pin_orders.get(&conversation).copied(),
                recent_activity: activity.get(&conversation).copied().unwrap_or(0),
                conversation,
            })
            .collect::<Vec<_>>();
        conversations.sort_by(compare_pin_conversations);
        Ok(PinConversationResult {
            selection,
            selected_labels: labels.selected,
            unavailable_labels: labels.unavailable_selected,
            conversations,
        })
    }

    fn remove_pin(&self, conversation: &ConversationId) -> Result<bool> {
        let rowid =
            self.local_metadata_rows()?
                .into_iter()
                .find_map(|(rowid, record)| match record {
                    LocalMetadataRecord::Pin(pin) if pin.conversation == *conversation => {
                        Some(rowid)
                    }
                    _ => None,
                });
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![rowid],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Create a label with a cryptographically random stable id.
    ///
    /// Id collisions are retried without overwriting, and the bounded retry
    /// budget fails closed. Duplicate visible names are intentionally allowed.
    pub fn create_label(
        &self,
        name: &str,
        color: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<LabelRecord> {
        validate_new_label(name, color)?;
        let rows = self.local_metadata_rows()?;
        let existing = rows
            .iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Label(label) => Some(label.id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        if existing.len() >= MAX_LABELS {
            return Err(StoreError::LabelLimit);
        }

        for _ in 0..LABEL_ID_RETRY_LIMIT {
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            if existing.contains(&id) {
                continue;
            }
            let label = LabelRecord {
                id,
                name: name.to_owned(),
                color: color.to_owned(),
            };
            let sealed =
                self.seal_local_metadata(&LocalMetadataRecord::Label(label.clone()), rng)?;
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO local_metadata (blob) VALUES (?1)",
                params![sealed],
            )?;
            tx.commit()?;
            return Ok(label);
        }
        Err(StoreError::LabelIdCollision)
    }

    /// Read label definitions in deterministic durable insertion order.
    pub fn labels(&self) -> Result<Vec<LabelRecord>> {
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Label(label) => Some(label),
                _ => None,
            })
            .collect())
    }

    /// Read one label definition by its stable id.
    pub fn label(&self, id: &[u8; 16]) -> Result<Option<LabelRecord>> {
        Ok(self
            .get_local_metadata(&LocalMetadataKey::Label(*id))?
            .and_then(|record| match record {
                LocalMetadataRecord::Label(label) => Some(label),
                _ => None,
            }))
    }

    /// Atomically replace a label's exact name and canonical color in place.
    ///
    /// The stable id, memberships, and insertion row remain unchanged.
    pub fn update_label(
        &self,
        id: &[u8; 16],
        name: &str,
        color: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<LabelRecord> {
        validate_new_label(name, color)?;
        let rowid = self
            .local_metadata_rows()?
            .into_iter()
            .find_map(|(rowid, record)| match record {
                LocalMetadataRecord::Label(label) if label.id == *id => Some(rowid),
                _ => None,
            })
            .ok_or(StoreError::UnknownLabel)?;
        let label = LabelRecord {
            id: *id,
            name: name.to_owned(),
            color: color.to_owned(),
        };
        let sealed = self.seal_local_metadata(&LocalMetadataRecord::Label(label.clone()), rng)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE local_metadata SET blob = ?2 WHERE rowid_ = ?1",
            params![rowid, sealed],
        )?;
        tx.commit()?;
        Ok(label)
    }

    /// Count every durable membership for a label, including stale targets.
    pub fn label_assignment_count(&self, id: &[u8; 16]) -> Result<usize> {
        if self.label(id)?.is_none() {
            return Err(StoreError::UnknownLabel);
        }
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .filter(|(_, record)| {
                matches!(record, LocalMetadataRecord::LabelAssignment(assignment) if assignment.label == *id)
            })
            .count())
    }

    /// Atomically delete a label and every one of its memberships.
    ///
    /// Returns the deleted assignment count. Any SQLite failure rolls the
    /// complete cascade back, so restart cannot expose half-deleted state.
    pub fn delete_label(&self, id: &[u8; 16]) -> Result<usize> {
        let rows = self.local_metadata_rows()?;
        let mut label_row = None;
        let mut assignment_rows = Vec::new();
        for (rowid, record) in rows {
            match record {
                LocalMetadataRecord::Label(label) if label.id == *id => label_row = Some(rowid),
                LocalMetadataRecord::LabelAssignment(assignment) if assignment.label == *id => {
                    assignment_rows.push(rowid);
                }
                _ => {}
            }
        }
        let label_row = label_row.ok_or(StoreError::UnknownLabel)?;
        let assignment_count = assignment_rows.len();
        let tx = self.conn.unchecked_transaction()?;
        for rowid in assignment_rows {
            tx.execute(
                "DELETE FROM local_metadata WHERE rowid_ = ?1",
                params![rowid],
            )?;
        }
        tx.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![label_row],
        )?;
        tx.commit()?;
        Ok(assignment_count)
    }

    /// Idempotently assign an existing label to an available typed target.
    ///
    /// Returns `true` when a new durable membership was created and `false`
    /// when it already existed.
    pub fn assign_label(
        &self,
        label: &[u8; 16],
        conversation: &ConversationId,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let rows = self.local_metadata_rows()?;
        let mut label_exists = false;
        let mut assignment_count = 0usize;
        let mut conversation_count = 0usize;
        for (_, record) in &rows {
            match record {
                LocalMetadataRecord::Label(record) if record.id == *label => label_exists = true,
                LocalMetadataRecord::LabelAssignment(record) => {
                    if record.label == *label && record.conversation == *conversation {
                        return Ok(false);
                    }
                    assignment_count += 1;
                    if record.conversation == *conversation {
                        conversation_count += 1;
                    }
                }
                _ => {}
            }
        }
        if !label_exists {
            return Err(StoreError::UnknownLabel);
        }
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        if assignment_count >= MAX_LABEL_ASSIGNMENTS {
            return Err(StoreError::LabelAssignmentLimit);
        }
        if conversation_count >= MAX_LABELS_PER_CONVERSATION {
            return Err(StoreError::ConversationLabelLimit);
        }
        let assignment = LocalMetadataRecord::LabelAssignment(LabelAssignment {
            label: *label,
            conversation: conversation.clone(),
        });
        let sealed = self.seal_local_metadata(&assignment, rng)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO local_metadata (blob) VALUES (?1)",
            params![sealed],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Idempotently remove one exact membership, including a stale one.
    ///
    /// Returns `true` when a row was deleted and `false` for the honest absent
    /// no-op. Target availability is deliberately not required for cleanup.
    pub fn unassign_label(&self, label: &[u8; 16], conversation: &ConversationId) -> Result<bool> {
        let rowid =
            self.local_metadata_rows()?
                .into_iter()
                .find_map(|(rowid, record)| match record {
                    LocalMetadataRecord::LabelAssignment(assignment)
                        if assignment.label == *label
                            && assignment.conversation == *conversation =>
                    {
                        Some(rowid)
                    }
                    _ => None,
                });
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM local_metadata WHERE rowid_ = ?1",
            params![rowid],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Active conversation membership for one label in durable insertion order.
    pub fn label_members(&self, label: &[u8; 16]) -> Result<Vec<ConversationId>> {
        if self.label(label)?.is_none() {
            return Err(StoreError::UnknownLabel);
        }
        let available = self.available_conversations()?;
        Ok(self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::LabelAssignment(assignment)
                    if assignment.label == *label
                        && available.contains(&assignment.conversation) =>
                {
                    Some(assignment.conversation)
                }
                _ => None,
            })
            .collect())
    }

    /// Active labels for one available conversation in label insertion order.
    pub fn labels_for_conversation(
        &self,
        conversation: &ConversationId,
    ) -> Result<Vec<LabelRecord>> {
        if !self.conversation_available(conversation)? {
            return Err(StoreError::UnavailableConversation);
        }
        let rows = self.local_metadata_rows()?;
        let assigned = rows
            .iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::LabelAssignment(assignment)
                    if assignment.conversation == *conversation =>
                {
                    Some(assignment.label)
                }
                _ => None,
            })
            .collect::<HashSet<_>>();
        Ok(rows
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Label(label) if assigned.contains(&label.id) => Some(label),
                _ => None,
            })
            .collect())
    }

    /// Report stale durable memberships without exposing sealed row bytes.
    pub fn stale_label_assignments(&self) -> Result<Vec<StaleLabelAssignment>> {
        let rows = self.local_metadata_rows()?;
        let labels = rows
            .iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::Label(label) => Some(label.id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let available = self.available_conversations()?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::LabelAssignment(assignment) => {
                    let label_exists = labels.contains(&assignment.label);
                    let target_exists = available.contains(&assignment.conversation);
                    let reason = match (label_exists, target_exists) {
                        (true, true) => return None,
                        (false, true) => StaleLabelReason::MissingLabel,
                        (true, false) => StaleLabelReason::UnavailableConversation,
                        (false, false) => StaleLabelReason::MissingLabelAndConversation,
                    };
                    Some(StaleLabelAssignment {
                        label: assignment.label,
                        conversation: assignment.conversation,
                        reason,
                    })
                }
                _ => None,
            })
            .collect())
    }

    /// Remove one exact membership only if it is still stale at commit time.
    pub fn cleanup_stale_label_assignment(
        &self,
        label: &[u8; 16],
        conversation: &ConversationId,
    ) -> Result<bool> {
        let stale = self
            .stale_label_assignments()?
            .into_iter()
            .any(|record| record.label == *label && record.conversation == *conversation);
        if !stale {
            return Err(StoreError::LabelAssignmentActive);
        }
        self.unassign_label(label, conversation)
    }

    /// Filter every eligible typed conversation using local any/all semantics.
    ///
    /// Selected ids are deduplicated in caller order. Missing definitions are
    /// returned honestly and removed from the active selection; an empty active
    /// selection means no label filter.
    pub fn filter_label_conversations(
        &self,
        selected: &[[u8; 16]],
        mode: LabelFilterMode,
    ) -> Result<LabelFilterResult> {
        let definitions = self
            .labels()?
            .into_iter()
            .map(|label| label.id)
            .collect::<HashSet<_>>();
        let mut canonical = Vec::new();
        for id in selected {
            if !canonical.contains(id) {
                if canonical.len() >= MAX_LABELS {
                    return Err(StoreError::LabelLimit);
                }
                canonical.push(*id);
            }
        }
        let mut active = Vec::new();
        let mut unavailable_selected = Vec::new();
        for id in canonical {
            if definitions.contains(&id) {
                active.push(id);
            } else {
                unavailable_selected.push(id);
            }
        }

        let eligible = self.eligible_conversations()?;
        if active.is_empty() {
            return Ok(LabelFilterResult {
                selected: active,
                unavailable_selected,
                conversations: eligible,
            });
        }
        let available = eligible.iter().cloned().collect::<HashSet<_>>();
        let assignments = self
            .local_metadata_rows()?
            .into_iter()
            .filter_map(|(_, record)| match record {
                LocalMetadataRecord::LabelAssignment(assignment)
                    if definitions.contains(&assignment.label)
                        && available.contains(&assignment.conversation) =>
                {
                    Some((assignment.label, assignment.conversation))
                }
                _ => None,
            })
            .collect::<HashSet<_>>();
        let conversations = eligible
            .into_iter()
            .filter(|conversation| match mode {
                LabelFilterMode::Any => active
                    .iter()
                    .any(|label| assignments.contains(&(*label, conversation.clone()))),
                LabelFilterMode::All => active
                    .iter()
                    .all(|label| assignments.contains(&(*label, conversation.clone()))),
            })
            .collect();
        Ok(LabelFilterResult {
            selected: active,
            unavailable_selected,
            conversations,
        })
    }

    fn conversation_available(&self, conversation: &ConversationId) -> Result<bool> {
        match conversation {
            ConversationId::Peer(peer) => Ok(self.get_contact(peer)?.is_some()),
            ConversationId::Group(group) => Ok(self.get_group(group)?.is_some()),
            ConversationId::NoteToSelf => Ok(true),
        }
    }

    fn available_conversations(&self) -> Result<HashSet<ConversationId>> {
        Ok(self.eligible_conversations()?.into_iter().collect())
    }

    fn eligible_conversations(&self) -> Result<Vec<ConversationId>> {
        let mut peers = self
            .contacts()?
            .into_iter()
            .map(|contact| contact.peer)
            .collect::<Vec<_>>();
        peers.sort_unstable();
        let mut groups = self
            .groups()?
            .into_iter()
            .map(|group| group.id)
            .collect::<Vec<_>>();
        groups.sort_unstable();
        let mut conversations = Vec::with_capacity(1 + peers.len() + groups.len());
        conversations.push(ConversationId::NoteToSelf);
        conversations.extend(peers.into_iter().map(ConversationId::Peer));
        conversations.extend(groups.into_iter().map(ConversationId::Group));
        Ok(conversations)
    }

    fn conversation_activity(&self) -> Result<HashMap<ConversationId, u64>> {
        let mut activity = HashMap::<ConversationId, u64>::new();
        for message in self.all_messages()? {
            activity
                .entry(ConversationId::Peer(message.peer))
                .and_modify(|current| *current = (*current).max(message.timestamp))
                .or_insert(message.timestamp);
        }
        for message in self.all_group_messages()? {
            activity
                .entry(ConversationId::Group(message.group))
                .and_modify(|current| *current = (*current).max(message.timestamp))
                .or_insert(message.timestamp);
        }
        for message in self.note_messages()? {
            activity
                .entry(ConversationId::NoteToSelf)
                .and_modify(|current| *current = (*current).max(message.timestamp))
                .or_insert(message.timestamp);
        }
        Ok(activity)
    }

    fn seal_local_metadata(
        &self,
        record: &LocalMetadataRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let encoded = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        let mut versioned = Vec::with_capacity(RECORD_MAGIC_V1.len() + encoded.len());
        versioned.extend_from_slice(RECORD_MAGIC_V1);
        versioned.extend_from_slice(&encoded);
        Ok(self.k_local_metadata.seal(RECORD_AD, &versioned, rng))
    }

    fn local_metadata_rows(&self) -> Result<Vec<(i64, LocalMetadataRecord)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM local_metadata ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_local_metadata.open(RECORD_AD, &sealed)?;
            let encoded = plain
                .strip_prefix(RECORD_MAGIC_V1)
                .ok_or(StoreError::Serialization)?;
            let (record, remainder): (LocalMetadataRecord, &[u8]) =
                postcard::take_from_bytes(encoded).map_err(|_| StoreError::Serialization)?;
            if !remainder.is_empty() {
                return Err(StoreError::Serialization);
            }
            record.validate()?;
            records.push((rowid, record));
        }
        Ok(records)
    }
}

fn compare_pins(
    left: &PinRecord,
    right: &PinRecord,
    activity: &HashMap<ConversationId, u64>,
) -> Ordering {
    left.order
        .cmp(&right.order)
        .then_with(|| {
            activity
                .get(&right.conversation)
                .copied()
                .unwrap_or(0)
                .cmp(&activity.get(&left.conversation).copied().unwrap_or(0))
        })
        .then_with(|| compare_conversations(&left.conversation, &right.conversation))
}

fn compare_pin_conversations(
    left: &PinConversationRecord,
    right: &PinConversationRecord,
) -> Ordering {
    match (left.pin_order, right.pin_order) {
        (Some(left_order), Some(right_order)) => left_order
            .cmp(&right_order)
            .then_with(|| right.recent_activity.cmp(&left.recent_activity))
            .then_with(|| compare_conversations(&left.conversation, &right.conversation)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => right
            .recent_activity
            .cmp(&left.recent_activity)
            .then_with(|| compare_conversations(&left.conversation, &right.conversation)),
    }
}

fn compare_conversations(left: &ConversationId, right: &ConversationId) -> Ordering {
    let rank = |conversation: &ConversationId| match conversation {
        ConversationId::NoteToSelf => 0u8,
        ConversationId::Peer(_) => 1u8,
        ConversationId::Group(_) => 2u8,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (ConversationId::Peer(left), ConversationId::Peer(right))
            | (ConversationId::Group(left), ConversationId::Group(right)) => left.cmp(right),
            _ => Ordering::Equal,
        })
}

fn validate_new_label(name: &str, color: &str) -> Result<()> {
    if !valid_label_name(name) {
        return Err(StoreError::InvalidLabelName);
    }
    if !valid_label_color(color) {
        return Err(StoreError::InvalidLabelColor);
    }
    Ok(())
}

fn validate_new_folder(name: &str) -> Result<()> {
    if valid_folder_name(name) {
        Ok(())
    } else {
        Err(StoreError::InvalidFolderName)
    }
}

#[cfg(test)]
mod label_tests {
    use std::collections::{BTreeSet, VecDeque};

    use proptest::prelude::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use rand_core::{CryptoRng, Error as RandError};
    use rusqlite::Connection;

    use kult_crypto::KdfProfile;

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    struct ScriptedRng {
        bytes: VecDeque<u8>,
        fallback: u8,
    }

    impl ScriptedRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes: bytes.into(),
                fallback: 0xa5,
            }
        }
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.bytes.pop_front().unwrap_or(self.fallback);
                self.fallback = self.fallback.wrapping_add(17);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ScriptedRng {}

    fn store_at(path: &std::path::Path, seed: u64) -> (Store, StdRng) {
        let mut rng = StdRng::seed_from_u64(seed);
        let store = Store::create(path, b"pass", TEST_KDF, &mut rng).unwrap();
        (store, rng)
    }

    fn insert_direct(
        store: &Store,
        records: impl IntoIterator<Item = LocalMetadataRecord>,
        rng: &mut impl CryptoRngCore,
    ) {
        let tx = store.conn.unchecked_transaction().unwrap();
        for record in records {
            record.validate().unwrap();
            let sealed = store.seal_local_metadata(&record, rng).unwrap();
            tx.execute(
                "INSERT INTO local_metadata (blob) VALUES (?1)",
                params![sealed],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    #[test]
    fn folder_exact_unicode_whitespace_duplicates_and_collision_retry() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("folders.db"), 101);
        let exact = "e\u{301} 👩🏽‍🚀 \u{2067}עברית\u{2069}";
        let first = store.create_folder(exact, &mut rng).unwrap();
        let second = store.create_folder(exact, &mut rng).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(first.name.as_bytes(), exact.as_bytes());
        assert_eq!(store.folders().unwrap(), vec![first.clone(), second]);

        let fixed = "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{0020}\u{0085}\u{200e}\u{200f}\u{2028}\u{2029}";
        assert!(matches!(
            store.create_folder(fixed, &mut rng),
            Err(StoreError::InvalidFolderName)
        ));
        assert!(store.create_folder("\u{00a0}", &mut rng).is_ok());
        let exact_limit = "é".repeat(MAX_LOCAL_METADATA_STRING_BYTES / 2);
        assert!(store.create_folder(&exact_limit, &mut rng).is_ok());
        assert!(matches!(
            store.create_folder(&(exact_limit + "a"), &mut rng),
            Err(StoreError::InvalidFolderName)
        ));

        insert_direct(
            &store,
            [LocalMetadataRecord::Folder(FolderRecord {
                id: [7; 16],
                name: "collision".to_owned(),
                order: 99,
            })],
            &mut rng,
        );
        let mut retry_rng = ScriptedRng::new(
            [vec![7; 16], vec![8; 16], vec![9; 64]]
                .into_iter()
                .flatten()
                .collect(),
        );
        assert_eq!(
            store.create_folder("retry", &mut retry_rng).unwrap().id,
            [8; 16]
        );
        let mut exhausted = ScriptedRng::new(vec![7; 16 * FOLDER_ID_RETRY_LIMIT]);
        assert!(matches!(
            store.create_folder("never", &mut exhausted),
            Err(StoreError::FolderIdCollision)
        ));
    }

    #[test]
    fn folder_order_rename_reorder_and_extreme_append_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("folders.db"), 102);
        insert_direct(
            &store,
            [
                LocalMetadataRecord::Folder(FolderRecord {
                    id: [2; 16],
                    name: "second tie".to_owned(),
                    order: 7,
                }),
                LocalMetadataRecord::Folder(FolderRecord {
                    id: [1; 16],
                    name: "first tie".to_owned(),
                    order: 7,
                }),
                LocalMetadataRecord::Folder(FolderRecord {
                    id: [3; 16],
                    name: "extreme".to_owned(),
                    order: u32::MAX,
                }),
            ],
            &mut rng,
        );
        assert_eq!(
            store
                .folders()
                .unwrap()
                .iter()
                .map(|folder| folder.id)
                .collect::<Vec<_>>(),
            vec![[2; 16], [1; 16], [3; 16]]
        );
        let appended = store.create_folder("appended", &mut rng).unwrap();
        assert_eq!(appended.order, 3);
        assert_eq!(store.folders().unwrap().last().unwrap().id, appended.id);

        let renamed = store
            .rename_folder(&[1; 16], "exact renamed 🧭", &mut rng)
            .unwrap();
        assert_eq!(renamed.id, [1; 16]);
        assert_eq!(renamed.order, 1);
        let order = vec![appended.id, [3; 16], [1; 16], [2; 16]];
        let reordered = store.reorder_folders(&order, &mut rng).unwrap();
        assert_eq!(
            reordered.iter().map(|folder| folder.id).collect::<Vec<_>>(),
            order
        );
        assert_eq!(
            reordered
                .iter()
                .map(|folder| folder.order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert!(matches!(
            store.reorder_folders(&[appended.id, appended.id], &mut rng),
            Err(StoreError::InvalidFolderOrder)
        ));
        assert!(matches!(
            store.reorder_folders(&[[9; 16], [3; 16], [1; 16], [2; 16]], &mut rng),
            Err(StoreError::InvalidFolderOrder)
        ));
    }

    #[test]
    fn folder_move_unfile_delete_stale_and_recreate_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("folders.db");
        let (store, mut rng) = store_at(&db, 103);
        let first = store.create_folder("Trip", &mut rng).unwrap();
        let second = store.create_folder("Trip", &mut rng).unwrap();
        let note = ConversationId::NoteToSelf;
        assert_eq!(
            store
                .folder_conversations(FolderSelection::All)
                .unwrap()
                .conversations,
            vec![note.clone()]
        );
        assert_eq!(
            store
                .folder_conversations(FolderSelection::Unfiled)
                .unwrap()
                .conversations,
            vec![note.clone()]
        );
        assert!(store
            .move_conversation_to_folder(&note, &first.id, &mut rng)
            .unwrap());
        assert!(!store
            .move_conversation_to_folder(&note, &first.id, &mut rng)
            .unwrap());
        assert_eq!(store.folder_members(&first.id).unwrap(), vec![note.clone()]);
        assert_eq!(
            store.folder_for_conversation(&note).unwrap(),
            Some(first.clone())
        );
        assert!(store
            .move_conversation_to_folder(&note, &second.id, &mut rng)
            .unwrap());
        assert!(store.folder_members(&first.id).unwrap().is_empty());
        assert_eq!(
            store.folder_members(&second.id).unwrap(),
            vec![note.clone()]
        );
        assert!(store.unfile_conversation(&note).unwrap());
        assert!(!store.unfile_conversation(&note).unwrap());

        assert!(store
            .move_conversation_to_folder(&note, &first.id, &mut rng)
            .unwrap());
        assert_eq!(store.folder_assignment_count(&first.id).unwrap(), 1);
        assert_eq!(store.delete_folder(&first.id).unwrap(), 1);
        assert_eq!(store.folder_for_conversation(&note).unwrap(), None);
        let recreated = store.create_folder("Trip", &mut rng).unwrap();
        assert_ne!(recreated.id, first.id);
        assert!(store.folder_members(&recreated.id).unwrap().is_empty());

        insert_direct(
            &store,
            [LocalMetadataRecord::FolderAssignment(FolderAssignment {
                conversation: note.clone(),
                folder: [0xee; 16],
            })],
            &mut rng,
        );
        assert_eq!(
            store.stale_folder_assignments().unwrap(),
            vec![StaleFolderAssignment {
                folder: [0xee; 16],
                conversation: note.clone(),
                reason: StaleFolderReason::MissingFolder,
            }]
        );
        assert_eq!(store.folder_for_conversation(&note).unwrap(), None);
        assert_eq!(
            store
                .folder_conversations(FolderSelection::Unfiled)
                .unwrap()
                .conversations,
            vec![note.clone()]
        );
        assert!(store
            .cleanup_stale_folder_assignment(&[0xee; 16], &note)
            .unwrap());
        assert!(store
            .move_conversation_to_folder(&note, &recreated.id, &mut rng)
            .unwrap());
        assert!(matches!(
            store.cleanup_stale_folder_assignment(&recreated.id, &note),
            Err(StoreError::FolderAssignmentActive)
        ));
        let missing_peer = ConversationId::Peer([0xdd; 32]);
        let missing_group = ConversationId::Group([0xcc; 32]);
        insert_direct(
            &store,
            [
                LocalMetadataRecord::FolderAssignment(FolderAssignment {
                    conversation: missing_peer.clone(),
                    folder: recreated.id,
                }),
                LocalMetadataRecord::FolderAssignment(FolderAssignment {
                    conversation: missing_group.clone(),
                    folder: [0xab; 16],
                }),
            ],
            &mut rng,
        );
        assert_eq!(
            store.stale_folder_assignments().unwrap(),
            vec![
                StaleFolderAssignment {
                    folder: recreated.id,
                    conversation: missing_peer.clone(),
                    reason: StaleFolderReason::UnavailableConversation,
                },
                StaleFolderAssignment {
                    folder: [0xab; 16],
                    conversation: missing_group.clone(),
                    reason: StaleFolderReason::MissingFolderAndConversation,
                },
            ]
        );
        assert!(store
            .cleanup_stale_folder_assignment(&recreated.id, &missing_peer)
            .unwrap());
        assert!(store
            .cleanup_stale_folder_assignment(&[0xab; 16], &missing_group)
            .unwrap());
        drop(store);
        let reopened = Store::open(&db, b"pass").unwrap();
        assert!(reopened.stale_folder_assignments().unwrap().is_empty());
    }

    #[test]
    fn folder_exact_limits_keep_restored_rows_manageable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("folders.db"), 104);
        let folders = (0..MAX_FOLDERS)
            .map(|index| {
                LocalMetadataRecord::Folder(FolderRecord {
                    id: (index as u128).to_le_bytes(),
                    name: format!("folder {index}"),
                    order: index as u32,
                })
            })
            .collect::<Vec<_>>();
        insert_direct(&store, folders, &mut rng);
        assert!(matches!(
            store.create_folder("one over", &mut rng),
            Err(StoreError::FolderLimit)
        ));
        assert_eq!(store.folders().unwrap().len(), MAX_FOLDERS);
        assert_eq!(store.delete_folder(&[0; 16]).unwrap(), 0);
        assert!(store.create_folder("replacement", &mut rng).is_ok());

        let destination = store.folders().unwrap()[0].id;
        insert_direct(
            &store,
            (0..MAX_FOLDER_ASSIGNMENTS).map(|index| {
                let mut peer = [0u8; 32];
                peer[..8].copy_from_slice(&(index as u64).to_le_bytes());
                LocalMetadataRecord::FolderAssignment(FolderAssignment {
                    conversation: ConversationId::Peer(peer),
                    folder: destination,
                })
            }),
            &mut rng,
        );
        assert!(matches!(
            store.move_conversation_to_folder(&ConversationId::NoteToSelf, &destination, &mut rng,),
            Err(StoreError::FolderAssignmentLimit)
        ));
        let stale = store.stale_folder_assignments().unwrap();
        assert_eq!(stale.len(), MAX_FOLDER_ASSIGNMENTS);
        assert!(store
            .cleanup_stale_folder_assignment(&destination, &stale[0].conversation)
            .unwrap());
        assert!(store
            .move_conversation_to_folder(&ConversationId::NoteToSelf, &destination, &mut rng,)
            .unwrap());
    }

    #[test]
    fn folder_create_rename_reorder_and_cascade_failures_are_atomic_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("folders.db");
        let (store, mut rng) = store_at(&db, 105);

        let raw = Connection::open(&db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_folder_create BEFORE INSERT ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected folder create'); END;",
        )
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.create_folder("create fails", &mut rng),
            Err(StoreError::Db(_))
        ));
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_folder_create")
            .unwrap();
        drop(raw);
        assert!(store.folders().unwrap().is_empty());

        let first = store.create_folder("first", &mut rng).unwrap();
        let second = store.create_folder("second", &mut rng).unwrap();
        store
            .move_conversation_to_folder(&ConversationId::NoteToSelf, &first.id, &mut rng)
            .unwrap();
        let before = store.folders().unwrap();
        let raw = Connection::open(&db).unwrap();
        let first_row: i64 = raw
            .query_row(
                "SELECT rowid_ FROM local_metadata ORDER BY rowid_ LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_folder_rename BEFORE UPDATE ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected folder rename'); END;",
        )
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.rename_folder(&first.id, "changed", &mut rng),
            Err(StoreError::Db(_))
        ));
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_folder_rename")
            .unwrap();
        raw.execute_batch(&format!(
            "CREATE TRIGGER fail_folder_reorder BEFORE UPDATE ON local_metadata WHEN OLD.rowid_ = {first_row} BEGIN SELECT RAISE(FAIL, 'injected folder reorder'); END;"
        ))
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.reorder_folders(&[second.id, first.id], &mut rng),
            Err(StoreError::Db(_))
        ));
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_folder_reorder")
            .unwrap();
        raw.execute_batch(&format!(
            "CREATE TRIGGER fail_folder_cascade BEFORE DELETE ON local_metadata WHEN OLD.rowid_ = {first_row} BEGIN SELECT RAISE(FAIL, 'injected folder cascade'); END;"
        ))
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.delete_folder(&first.id),
            Err(StoreError::Db(_))
        ));
        drop(store);

        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_folder_cascade")
            .unwrap();
        drop(raw);
        let reopened = Store::open(&db, b"pass").unwrap();
        assert_eq!(reopened.folders().unwrap(), before);
        assert_eq!(
            reopened
                .folder_for_conversation(&ConversationId::NoteToSelf)
                .unwrap()
                .unwrap()
                .id,
            first.id
        );
    }

    proptest! {
        #[test]
        fn arbitrary_valid_folder_operations_match_a_single_membership_model(
            ops in prop::collection::vec(any::<u8>(), 0..160)
        ) {
            let dir = tempfile::tempdir().unwrap();
            let (store, mut rng) = store_at(&dir.path().join("folders.db"), 0x000b_1018);
            let mut model = Vec::<FolderRecord>::new();
            let mut assigned = None::<[u8; 16]>;

            for (step, op) in ops.into_iter().enumerate() {
                match op % 6 {
                    0 if model.len() < 12 => {
                        let name = if step % 2 == 0 {
                            format!("same 🧭 {step}")
                        } else {
                            "duplicate".to_owned()
                        };
                        model.push(store.create_folder(&name, &mut rng).unwrap());
                    }
                    1 if !model.is_empty() => {
                        let index = step % model.len();
                        let updated = store
                            .rename_folder(&model[index].id, &format!("e\u{301} {step}"), &mut rng)
                            .unwrap();
                        model[index] = updated;
                    }
                    2 if !model.is_empty() => {
                        let id = model[step % model.len()].id;
                        let changed = store
                            .move_conversation_to_folder(&ConversationId::NoteToSelf, &id, &mut rng)
                            .unwrap();
                        prop_assert_eq!(changed, assigned != Some(id));
                        assigned = Some(id);
                    }
                    3 => {
                        let changed = store.unfile_conversation(&ConversationId::NoteToSelf).unwrap();
                        prop_assert_eq!(changed, assigned.take().is_some());
                    }
                    4 if !model.is_empty() => {
                        let index = step % model.len();
                        let removed = model.remove(index);
                        let expected = usize::from(assigned == Some(removed.id));
                        prop_assert_eq!(store.delete_folder(&removed.id).unwrap(), expected);
                        if expected == 1 { assigned = None; }
                    }
                    5 if model.len() > 1 => {
                        let shift = step % model.len();
                        model.rotate_left(shift);
                        let ids = model.iter().map(|folder| folder.id).collect::<Vec<_>>();
                        model = store.reorder_folders(&ids, &mut rng).unwrap();
                    }
                    _ => {}
                }
                prop_assert_eq!(store.folders().unwrap(), model.clone());
                let actual = store
                    .folder_for_conversation(&ConversationId::NoteToSelf)
                    .unwrap()
                    .map(|folder| folder.id);
                prop_assert_eq!(actual, assigned);
            }
        }
    }

    #[test]
    fn exact_unicode_whitespace_and_color_contract() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("labels.db"), 1);
        let exact = "e\u{301} 👩🏽‍🚀 \u{2067}עברית\u{2069}";
        let label = store.create_label(exact, "purple", &mut rng).unwrap();
        assert_eq!(store.label(&label.id).unwrap().unwrap().name, exact);
        assert_eq!(store.label(&label.id).unwrap().unwrap().color, "purple");

        let fixed = "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{0020}\u{0085}\u{200e}\u{200f}\u{2028}\u{2029}";
        assert!(matches!(
            store.create_label("", "neutral", &mut rng),
            Err(StoreError::InvalidLabelName)
        ));
        assert!(matches!(
            store.create_label(fixed, "neutral", &mut rng),
            Err(StoreError::InvalidLabelName)
        ));
        let nbsp = store.create_label("\u{00a0}", "teal", &mut rng).unwrap();
        assert_eq!(nbsp.name, "\u{00a0}");

        let exact_limit = "é".repeat(MAX_LOCAL_METADATA_STRING_BYTES / 2);
        assert_eq!(exact_limit.len(), MAX_LOCAL_METADATA_STRING_BYTES);
        assert!(store.create_label(&exact_limit, "blue", &mut rng).is_ok());
        assert!(matches!(
            store.create_label(&(exact_limit + "a"), "blue", &mut rng),
            Err(StoreError::InvalidLabelName)
        ));
        assert!(matches!(
            store.create_label("valid", "warning", &mut rng),
            Err(StoreError::InvalidLabelColor)
        ));
        for color in LABEL_COLORS {
            assert!(valid_label_color(color));
            assert_eq!(render_label_color(color), color);
        }
        assert_eq!(render_label_color("legacy-css:red"), "neutral");
    }

    #[test]
    fn duplicate_names_have_distinct_ids_and_keep_insertion_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("labels.db");
        let (store, mut rng) = store_at(&db, 2);
        let first = store.create_label("Same", "red", &mut rng).unwrap();
        let second = store.create_label("Same", "blue", &mut rng).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(store.labels().unwrap(), vec![first.clone(), second.clone()]);

        let renamed = store
            .update_label(&first.id, "Same", "green", &mut rng)
            .unwrap();
        assert_eq!(renamed.id, first.id);
        assert_eq!(store.labels().unwrap(), vec![renamed, second]);
        drop(store);
        assert_eq!(
            Store::open(&db, b"pass").unwrap().labels().unwrap().len(),
            2
        );
    }

    #[test]
    fn random_ids_retry_collisions_and_fail_after_the_bounded_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut setup_rng) = store_at(&dir.path().join("labels.db"), 3);
        insert_direct(
            &store,
            [LocalMetadataRecord::Label(LabelRecord {
                id: [7; 16],
                name: "existing".to_owned(),
                color: "neutral".to_owned(),
            })],
            &mut setup_rng,
        );
        let mut retry_rng = ScriptedRng::new(
            [vec![7; 16], vec![8; 16], vec![9; 32]]
                .into_iter()
                .flatten()
                .collect(),
        );
        let created = store.create_label("new", "orange", &mut retry_rng).unwrap();
        assert_eq!(created.id, [8; 16]);
        assert_eq!(store.label(&[7; 16]).unwrap().unwrap().name, "existing");

        let mut exhausted = ScriptedRng::new(vec![7; 16 * LABEL_ID_RETRY_LIMIT]);
        assert!(matches!(
            store.create_label("never", "pink", &mut exhausted),
            Err(StoreError::LabelIdCollision)
        ));
        assert_eq!(store.labels().unwrap().len(), 2);
    }

    #[test]
    fn exact_definition_and_per_conversation_limits_are_non_destructive() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("labels.db"), 4);
        let labels = (0..MAX_LABELS)
            .map(|index| {
                LocalMetadataRecord::Label(LabelRecord {
                    id: (index as u128).to_le_bytes(),
                    name: format!("label {index}"),
                    color: "neutral".to_owned(),
                })
            })
            .collect::<Vec<_>>();
        insert_direct(&store, labels, &mut rng);
        assert_eq!(store.labels().unwrap().len(), MAX_LABELS);
        assert!(matches!(
            store.create_label("one over", "neutral", &mut rng),
            Err(StoreError::LabelLimit)
        ));
        assert_eq!(store.labels().unwrap().len(), MAX_LABELS);

        for index in 0..MAX_LABELS_PER_CONVERSATION {
            assert!(store
                .assign_label(
                    &(index as u128).to_le_bytes(),
                    &ConversationId::NoteToSelf,
                    &mut rng,
                )
                .unwrap());
        }
        assert_eq!(
            store
                .labels_for_conversation(&ConversationId::NoteToSelf)
                .unwrap()
                .len(),
            MAX_LABELS_PER_CONVERSATION
        );
        assert!(matches!(
            store.assign_label(
                &(MAX_LABELS_PER_CONVERSATION as u128).to_le_bytes(),
                &ConversationId::NoteToSelf,
                &mut rng,
            ),
            Err(StoreError::ConversationLabelLimit)
        ));
    }

    #[test]
    fn exact_aggregate_assignment_limit_refuses_only_growth() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("labels.db"), 5);
        let label = LabelRecord {
            id: [4; 16],
            name: "large restored set".to_owned(),
            color: "neutral".to_owned(),
        };
        insert_direct(
            &store,
            core::iter::once(LocalMetadataRecord::Label(label.clone())).chain(
                (0..MAX_LABEL_ASSIGNMENTS).map(|index| {
                    let mut peer = [0u8; 32];
                    peer[..8].copy_from_slice(&(index as u64).to_le_bytes());
                    LocalMetadataRecord::LabelAssignment(LabelAssignment {
                        label: label.id,
                        conversation: ConversationId::Peer(peer),
                    })
                }),
            ),
            &mut rng,
        );
        assert!(matches!(
            store.assign_label(&label.id, &ConversationId::NoteToSelf, &mut rng),
            Err(StoreError::LabelAssignmentLimit)
        ));
        assert!(!store
            .unassign_label(&[9; 16], &ConversationId::NoteToSelf)
            .unwrap());
        let stale = store.stale_label_assignments().unwrap();
        assert_eq!(stale.len(), MAX_LABEL_ASSIGNMENTS);
        assert!(store
            .cleanup_stale_label_assignment(&label.id, &stale[0].conversation)
            .unwrap());
        assert!(store
            .assign_label(&label.id, &ConversationId::NoteToSelf, &mut rng)
            .unwrap());
    }

    #[test]
    fn assign_unassign_filter_stale_and_delete_recreate_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("labels.db"), 6);
        let red = store.create_label("Trip", "red", &mut rng).unwrap();
        let blue = store.create_label("Trip", "blue", &mut rng).unwrap();
        assert!(store
            .assign_label(&red.id, &ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert!(!store
            .assign_label(&red.id, &ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert!(store
            .assign_label(&blue.id, &ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert_eq!(
            store.label_members(&red.id).unwrap(),
            vec![ConversationId::NoteToSelf]
        );
        assert_eq!(
            store
                .filter_label_conversations(&[red.id, red.id], LabelFilterMode::Any)
                .unwrap()
                .conversations,
            vec![ConversationId::NoteToSelf]
        );
        assert_eq!(
            store
                .filter_label_conversations(&[red.id, blue.id], LabelFilterMode::All)
                .unwrap()
                .conversations,
            vec![ConversationId::NoteToSelf]
        );

        let missing_target = ConversationId::Group([0x55; 32]);
        insert_direct(
            &store,
            [LocalMetadataRecord::LabelAssignment(LabelAssignment {
                label: red.id,
                conversation: missing_target.clone(),
            })],
            &mut rng,
        );
        assert_eq!(
            store.stale_label_assignments().unwrap(),
            vec![StaleLabelAssignment {
                label: red.id,
                conversation: missing_target.clone(),
                reason: StaleLabelReason::UnavailableConversation,
            }]
        );
        assert!(matches!(
            store.cleanup_stale_label_assignment(&red.id, &ConversationId::NoteToSelf),
            Err(StoreError::LabelAssignmentActive)
        ));

        assert_eq!(store.delete_label(&red.id).unwrap(), 2);
        let replacement = store.create_label("Trip", "red", &mut rng).unwrap();
        assert_ne!(replacement.id, red.id);
        assert!(store.label_members(&replacement.id).unwrap().is_empty());
        assert_eq!(
            store
                .labels_for_conversation(&ConversationId::NoteToSelf)
                .unwrap(),
            vec![blue.clone()]
        );
        assert!(store
            .unassign_label(&blue.id, &ConversationId::NoteToSelf)
            .unwrap());
        assert!(!store
            .unassign_label(&blue.id, &ConversationId::NoteToSelf)
            .unwrap());
    }

    #[test]
    fn unavailable_selection_is_reported_and_unknown_color_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("labels.db"), 7);
        let legacy = LabelRecord {
            id: [3; 16],
            name: "Legacy".to_owned(),
            color: "var(--private)".to_owned(),
        };
        store
            .put_local_metadata(&LocalMetadataRecord::Label(legacy.clone()), &mut rng)
            .unwrap();
        assert_eq!(
            store.label(&legacy.id).unwrap().unwrap().color,
            legacy.color
        );
        assert_eq!(render_label_color(&legacy.color), "neutral");
        let result = store
            .filter_label_conversations(&[[9; 16]], LabelFilterMode::Any)
            .unwrap();
        assert!(result.selected.is_empty());
        assert_eq!(result.unavailable_selected, vec![[9; 16]]);
        assert_eq!(result.conversations, vec![ConversationId::NoteToSelf]);
    }

    #[test]
    fn create_update_and_cascade_failures_are_atomic_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("labels.db");
        let (store, mut rng) = store_at(&db, 8);

        let raw = Connection::open(&db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_create BEFORE INSERT ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected create'); END;",
        )
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.create_label("create fails", "red", &mut rng),
            Err(StoreError::Db(_))
        ));
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_create").unwrap();
        drop(raw);
        assert!(store.labels().unwrap().is_empty());

        let label = store.create_label("before", "red", &mut rng).unwrap();
        store
            .assign_label(&label.id, &ConversationId::NoteToSelf, &mut rng)
            .unwrap();
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_update BEFORE UPDATE ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected update'); END;",
        )
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.update_label(&label.id, "after", "blue", &mut rng),
            Err(StoreError::Db(_))
        ));
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_update").unwrap();
        drop(raw);
        assert_eq!(store.label(&label.id).unwrap().unwrap().name, "before");

        let raw = Connection::open(&db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_cascade BEFORE DELETE ON local_metadata WHEN OLD.rowid_ = 1 BEGIN SELECT RAISE(FAIL, 'injected cascade'); END;",
        )
        .unwrap();
        drop(raw);
        assert!(matches!(
            store.delete_label(&label.id),
            Err(StoreError::Db(_))
        ));
        drop(store);
        let raw = Connection::open(&db).unwrap();
        raw.execute_batch("DROP TRIGGER fail_cascade").unwrap();
        drop(raw);
        let reopened = Store::open(&db, b"pass").unwrap();
        assert_eq!(reopened.label(&label.id).unwrap().unwrap().name, "before");
        assert_eq!(
            reopened.label_members(&label.id).unwrap(),
            vec![ConversationId::NoteToSelf]
        );
    }

    #[test]
    fn corrupt_sealed_rows_fail_safely_without_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("labels.db");
        let (store, mut rng) = store_at(&db, 9);
        store.create_label("secret", "pink", &mut rng).unwrap();
        drop(store);
        let raw = Connection::open(&db).unwrap();
        raw.execute(
            "UPDATE local_metadata SET blob = zeroblob(length(blob))",
            [],
        )
        .unwrap();
        drop(raw);
        let reopened = Store::open(&db, b"pass").unwrap();
        assert!(matches!(reopened.labels(), Err(StoreError::Crypto(_))));
    }

    #[test]
    fn pin_append_compaction_reorder_stale_cleanup_and_restart_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("pins.db");
        let (store, mut rng) = store_at(&db, 0xb11);
        let peer = ConversationId::Peer([1; 32]);
        let group = ConversationId::Group([2; 32]);
        insert_direct(
            &store,
            [
                LocalMetadataRecord::Pin(PinRecord {
                    conversation: group.clone(),
                    order: u32::MAX,
                }),
                LocalMetadataRecord::Pin(PinRecord {
                    conversation: peer.clone(),
                    order: u32::MAX,
                }),
            ],
            &mut rng,
        );

        assert!(store
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert!(!store
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert!(matches!(
            store.pin_conversation(&ConversationId::Peer([9; 32]), &mut rng),
            Err(StoreError::UnavailableConversation)
        ));
        assert_eq!(
            store
                .pins()
                .unwrap()
                .into_iter()
                .map(|status| (status.pin.conversation, status.pin.order, status.active))
                .collect::<Vec<_>>(),
            vec![
                (peer.clone(), 0, false),
                (group.clone(), 1, false),
                (ConversationId::NoteToSelf, 2, true),
            ]
        );

        let reordered = store
            .reorder_pins(
                &[ConversationId::NoteToSelf, group.clone(), peer.clone()],
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            reordered
                .iter()
                .map(|status| (&status.pin.conversation, status.pin.order))
                .collect::<Vec<_>>(),
            vec![(&ConversationId::NoteToSelf, 0), (&group, 1), (&peer, 2),]
        );
        assert!(matches!(
            store.reorder_pins(&[peer.clone(), group.clone()], &mut rng),
            Err(StoreError::InvalidPinOrder)
        ));
        assert!(matches!(
            store.cleanup_stale_pin(&ConversationId::NoteToSelf),
            Err(StoreError::PinActive)
        ));
        assert!(store.cleanup_stale_pin(&group).unwrap());
        assert!(!store.unpin_conversation(&group).unwrap());
        drop(store);

        let reopened = Store::open(&db, b"pass").unwrap();
        assert_eq!(
            reopened
                .pins()
                .unwrap()
                .into_iter()
                .map(|status| (status.pin.conversation, status.pin.order, status.active))
                .collect::<Vec<_>>(),
            vec![(ConversationId::NoteToSelf, 0, true), (peer, 2, false),]
        );
    }

    #[test]
    fn pin_limit_is_exact_and_legacy_over_limit_rows_remain_manageable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("pin-limit.db"), 0xb110);
        insert_direct(
            &store,
            (0..MAX_PINS).map(|index| {
                let mut peer = [0u8; 32];
                peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
                LocalMetadataRecord::Pin(PinRecord {
                    conversation: ConversationId::Peer(peer),
                    order: index as u32,
                })
            }),
            &mut rng,
        );
        assert!(matches!(
            store.pin_conversation(&ConversationId::NoteToSelf, &mut rng),
            Err(StoreError::PinLimit)
        ));
        let first = store.pins().unwrap()[0].pin.conversation.clone();
        assert!(store.unpin_conversation(&first).unwrap());
        assert!(store
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .unwrap());
        assert_eq!(store.pins().unwrap().len(), MAX_PINS);
    }

    #[test]
    fn stale_pin_reactivates_only_when_the_exact_typed_identity_returns() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut rng) = store_at(&dir.path().join("pin-reactivation.db"), 0xb115);
        let group_id = [7u8; 32];
        let group = ConversationId::Group(group_id);
        insert_direct(
            &store,
            [LocalMetadataRecord::Pin(PinRecord {
                conversation: group.clone(),
                order: 9,
            })],
            &mut rng,
        );
        assert!(!store.pin_state(&group).unwrap().unwrap().active);
        store
            .put_group(
                &crate::GroupRecord {
                    id: group_id,
                    name: "same exact identity".to_owned(),
                    creator: [8; 32],
                    members: Vec::new(),
                    secret: [9; 32],
                    prev_secret: None,
                    generation: 1,
                    sender_chain: vec![1],
                    sent_since_rotation: 0,
                    pending: Vec::new(),
                },
                &mut rng,
            )
            .unwrap();
        let reactivated = store.pin_state(&group).unwrap().unwrap();
        assert!(reactivated.active);
        assert_eq!(reactivated.pin.order, 9);
        assert!(!store.pin_conversation(&group, &mut rng).unwrap());
        store.delete_group(&group_id).unwrap();
        assert!(!store.pin_state(&group).unwrap().unwrap().active);
    }

    #[test]
    fn pin_append_compaction_reorder_unpin_and_cleanup_failures_are_atomic() {
        let dir = tempfile::tempdir().unwrap();

        let append_db = dir.path().join("pin-append-failure.db");
        let (append, mut rng) = store_at(&append_db, 0xb111);
        let raw = Connection::open(&append_db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_pin_append BEFORE INSERT ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected pin append'); END;",
        )
        .unwrap();
        assert!(append
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .is_err());
        assert!(append.pins().unwrap().is_empty());

        let compact_db = dir.path().join("pin-compact-failure.db");
        let (compact, mut rng) = store_at(&compact_db, 0xb112);
        let peer = ConversationId::Peer([1; 32]);
        let group = ConversationId::Group([2; 32]);
        insert_direct(
            &compact,
            [peer.clone(), group.clone()]
                .into_iter()
                .map(|conversation| {
                    LocalMetadataRecord::Pin(PinRecord {
                        conversation,
                        order: u32::MAX,
                    })
                }),
            &mut rng,
        );
        let raw = Connection::open(&compact_db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_pin_compact_insert BEFORE INSERT ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected pin compact insert'); END;",
        )
        .unwrap();
        assert!(compact
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .is_err());
        assert!(compact
            .pins()
            .unwrap()
            .iter()
            .all(|status| status.pin.order == u32::MAX));

        let mutation_db = dir.path().join("pin-mutation-failure.db");
        let (mutations, mut rng) = store_at(&mutation_db, 0xb113);
        insert_direct(
            &mutations,
            [
                LocalMetadataRecord::Pin(PinRecord {
                    conversation: peer.clone(),
                    order: 0,
                }),
                LocalMetadataRecord::Pin(PinRecord {
                    conversation: group.clone(),
                    order: 1,
                }),
            ],
            &mut rng,
        );
        mutations
            .pin_conversation(&ConversationId::NoteToSelf, &mut rng)
            .unwrap();
        let before = mutations.pins().unwrap();
        let raw = Connection::open(&mutation_db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_pin_reorder BEFORE UPDATE ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected pin reorder'); END;",
        )
        .unwrap();
        assert!(mutations
            .reorder_pins(
                &[ConversationId::NoteToSelf, group.clone(), peer.clone()],
                &mut rng,
            )
            .is_err());
        assert_eq!(mutations.pins().unwrap(), before);
        raw.execute_batch("DROP TRIGGER fail_pin_reorder").unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_pin_delete BEFORE DELETE ON local_metadata BEGIN SELECT RAISE(FAIL, 'injected pin delete'); END;",
        )
        .unwrap();
        assert!(mutations
            .unpin_conversation(&ConversationId::NoteToSelf)
            .is_err());
        assert!(mutations.cleanup_stale_pin(&peer).is_err());
        assert_eq!(mutations.pins().unwrap(), before);
    }

    proptest! {
        #[test]
        fn arbitrary_pin_sequences_match_a_small_durable_model(ops in prop::collection::vec(any::<u8>(), 0..160)) {
            let dir = tempfile::tempdir().unwrap();
            let (store, mut rng) = store_at(&dir.path().join("pin-model.db"), 0xb114);
            let stale = (0..8).map(|index| ConversationId::Peer([index + 1; 32])).collect::<Vec<_>>();
            insert_direct(
                &store,
                stale.iter().cloned().enumerate().map(|(order, conversation)| {
                    LocalMetadataRecord::Pin(PinRecord { conversation, order: order as u32 })
                }),
                &mut rng,
            );
            let mut model = stale.clone();

            for (step, op) in ops.into_iter().enumerate() {
                let candidate = if step % 3 == 0 {
                    ConversationId::NoteToSelf
                } else {
                    stale[step % stale.len()].clone()
                };
                match op % 5 {
                    0 => {
                        let changed = store.unpin_conversation(&candidate).unwrap();
                        let before = model.len();
                        model.retain(|item| item != &candidate);
                        prop_assert_eq!(changed, model.len() != before);
                    }
                    1 => {
                        let active = candidate == ConversationId::NoteToSelf;
                        let present = model.contains(&candidate);
                        let result = store.cleanup_stale_pin(&candidate);
                        if present && !active {
                            prop_assert!(result.unwrap());
                            model.retain(|item| item != &candidate);
                        } else {
                            prop_assert!(matches!(result, Err(StoreError::PinActive)));
                        }
                    }
                    2 | 4 => {
                        let present = model.contains(&ConversationId::NoteToSelf);
                        prop_assert_eq!(
                            store.pin_conversation(&ConversationId::NoteToSelf, &mut rng).unwrap(),
                            !present
                        );
                        if !present { model.push(ConversationId::NoteToSelf); }
                    }
                    _ => {
                        model.reverse();
                        store.reorder_pins(&model, &mut rng).unwrap();
                    }
                }
                prop_assert_eq!(
                    store.pins().unwrap().into_iter().map(|status| status.pin.conversation).collect::<Vec<_>>(),
                    model.clone()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_valid_operation_sequences_match_a_small_model(ops in prop::collection::vec(any::<u8>(), 0..160)) {
            let dir = tempfile::tempdir().unwrap();
            let (store, mut rng) = store_at(&dir.path().join("labels.db"), 0x18);
            let mut model = Vec::<LabelRecord>::new();
            let mut assigned = BTreeSet::<[u8; 16]>::new();

            for (step, op) in ops.into_iter().enumerate() {
                match op % 6 {
                    0 if model.len() < 12 => {
                        let name = if step % 2 == 0 { format!("same 🧭 {step}") } else { "duplicate".to_owned() };
                        let color = LABEL_COLORS[step % LABEL_COLORS.len()];
                        let label = store.create_label(&name, color, &mut rng).unwrap();
                        model.push(label);
                    }
                    1 if !model.is_empty() => {
                        let index = step % model.len();
                        let name = format!("e\u{301} {step}");
                        let color = LABEL_COLORS[(step + 3) % LABEL_COLORS.len()];
                        let updated = store.update_label(&model[index].id, &name, color, &mut rng).unwrap();
                        model[index] = updated;
                    }
                    2 if !model.is_empty() => {
                        let id = model[step % model.len()].id;
                        let changed = store.assign_label(&id, &ConversationId::NoteToSelf, &mut rng).unwrap();
                        prop_assert_eq!(changed, assigned.insert(id));
                    }
                    3 if !model.is_empty() => {
                        let id = model[step % model.len()].id;
                        let changed = store.unassign_label(&id, &ConversationId::NoteToSelf).unwrap();
                        prop_assert_eq!(changed, assigned.remove(&id));
                    }
                    4 if !model.is_empty() => {
                        let index = step % model.len();
                        let removed = model.remove(index);
                        let expected = usize::from(assigned.remove(&removed.id));
                        prop_assert_eq!(store.delete_label(&removed.id).unwrap(), expected);
                    }
                    _ => {}
                }
                prop_assert_eq!(store.labels().unwrap(), model.clone());
                let actual = store.labels_for_conversation(&ConversationId::NoteToSelf).unwrap();
                let expected = model.iter().filter(|label| assigned.contains(&label.id)).cloned().collect::<Vec<_>>();
                prop_assert_eq!(actual, expected);
            }
        }
    }
}
