//! Sealed local-only organization and presentation records (F5).
//!
//! These records never enter envelopes, DHT records, group state, or transport
//! hints. The SQLite table contains only an insertion-order row id and one
//! independently sealed blob, so copied databases reveal neither record keys
//! nor organization relationships.

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Result, Store, StoreError};

const RECORD_MAGIC_V1: &[u8; 4] = b"KLM1";
const RECORD_AD: &[u8] = b"local-metadata";

/// Maximum UTF-8 bytes in a folder name, label name, color token, media type,
/// preference key, or similar local-metadata string.
pub const MAX_LOCAL_METADATA_STRING_BYTES: usize = 256;
/// Maximum bytes in a saved message draft (1 MiB).
pub const MAX_DRAFT_BYTES: usize = 1024 * 1024;
/// Maximum bytes in one opaque UI preference value (64 KiB).
pub const MAX_UI_PREFERENCE_VALUE_BYTES: usize = 64 * 1024;
/// Maximum bytes in one already-sanitized custom icon (512 KiB).
pub const MAX_CUSTOM_ICON_BYTES: usize = 512 * 1024;

/// Stable identity and type of a conversation in local metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// An ordered pinned conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    /// Conversation being pinned.
    pub conversation: ConversationId,
    /// Manual pin position; ties fall back to recent activity in the shell.
    pub order: u32,
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
            Self::Folder(record) => string_ok(&record.name),
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
