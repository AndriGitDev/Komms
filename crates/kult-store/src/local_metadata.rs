//! Sealed local-only organization and presentation records (F5).
//!
//! These records never enter envelopes, DHT records, group state, or transport
//! hints. The SQLite table contains only an insertion-order row id and one
//! independently sealed blob, so copied databases reveal neither record keys
//! nor organization relationships.

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Result, Store, StoreError};

const RECORD_MAGIC_V1: &[u8; 4] = b"KLM1";
const RECORD_AD: &[u8] = b"local-metadata";

/// Maximum UTF-8 bytes in a folder name, label name, color token, media type,
/// preference key, or similar local-metadata string.
pub const MAX_LOCAL_METADATA_STRING_BYTES: usize = 256;
/// Maximum number of durable label definitions.
pub const MAX_LABELS: usize = 128;
/// Maximum number of durable label-to-conversation memberships.
pub const MAX_LABEL_ASSIGNMENTS: usize = 8_192;
/// Maximum number of labels assigned to one conversation.
pub const MAX_LABELS_PER_CONVERSATION: usize = 32;
/// Bounded attempts to mint a fresh random label id before failing closed.
pub const LABEL_ID_RETRY_LIMIT: usize = 16;
/// Canonical presentation tokens accepted for new label writes.
pub const LABEL_COLORS: [&str; 9] = [
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
];
/// Maximum bytes in a saved message draft (1 MiB).
pub const MAX_DRAFT_BYTES: usize = 1024 * 1024;
/// Maximum bytes in one opaque UI preference value (64 KiB).
pub const MAX_UI_PREFERENCE_VALUE_BYTES: usize = 64 * 1024;
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

fn validate_new_label(name: &str, color: &str) -> Result<()> {
    if !valid_label_name(name) {
        return Err(StoreError::InvalidLabelName);
    }
    if !valid_label_color(color) {
        return Err(StoreError::InvalidLabelColor);
    }
    Ok(())
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
