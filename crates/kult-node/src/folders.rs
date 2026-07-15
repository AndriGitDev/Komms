//! B10 private local conversation folders over the accepted F5 records.
//!
//! Folder operations classify local presentation only. They never encode
//! content, inspect transports, enqueue envelopes, advertise capabilities, or
//! alter message/history state.

use std::collections::HashSet;

use rand_core::CryptoRngCore;

use kult_store::{
    ConversationId, FolderRecord, FolderSelection as StoreFolderSelection, LabelFilterMode,
    StaleFolderReason as StoreStaleFolderReason,
};

use crate::{
    Event, FolderConversationInfo, FolderConversationList, FolderInfo, FolderSelection,
    LabelMatchMode, Node, NodeStaleFolderReason, Result, StaleFolderInfo,
};

impl Node {
    /// Create a private local folder with a collision-safe random stable id.
    pub fn create_folder(
        &mut self,
        name: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FolderInfo> {
        let folder = folder_info(self.store.create_folder(name, rng)?);
        self.events.push_back(Event::FoldersChanged);
        Ok(folder)
    }

    /// List folders in deterministic persisted manual order.
    pub fn folders(&self) -> Result<Vec<FolderInfo>> {
        Ok(self.store.folders()?.into_iter().map(folder_info).collect())
    }

    /// Get one folder by its exact stable id.
    pub fn folder(&self, id: &[u8; 16]) -> Result<FolderInfo> {
        self.store
            .folder(id)?
            .map(folder_info)
            .ok_or(kult_store::StoreError::UnknownFolder.into())
    }

    /// Rename one folder while preserving id, order, and membership.
    pub fn rename_folder(
        &mut self,
        id: &[u8; 16],
        name: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FolderInfo> {
        let before = self
            .store
            .folder(id)?
            .ok_or(kult_store::StoreError::UnknownFolder)?;
        let folder = folder_info(self.store.rename_folder(id, name, rng)?);
        if before.name != name {
            self.events.push_back(Event::FoldersChanged);
        }
        Ok(folder)
    }

    /// Atomically reorder the complete active folder id set.
    pub fn reorder_folders(
        &mut self,
        ordered: &[[u8; 16]],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<FolderInfo>> {
        let before = self
            .store
            .folders()?
            .into_iter()
            .map(|folder| folder.id)
            .collect::<Vec<_>>();
        let folders = self
            .store
            .reorder_folders(ordered, rng)?
            .into_iter()
            .map(folder_info)
            .collect::<Vec<_>>();
        if before != ordered {
            self.events.push_back(Event::FoldersChanged);
        }
        Ok(folders)
    }

    /// Count durable assignments before destructive deletion review.
    pub fn folder_delete_assignment_count(&self, id: &[u8; 16]) -> Result<usize> {
        Ok(self.store.folder_assignment_count(id)?)
    }

    /// Atomically delete a folder and cascade all its assignments to Unfiled.
    pub fn delete_folder(&mut self, id: &[u8; 16]) -> Result<usize> {
        let deleted = self.store.delete_folder(id)?;
        self.events.push_back(Event::FoldersChanged);
        Ok(deleted)
    }

    /// Idempotently move one exact typed conversation into one exact folder.
    pub fn move_conversation_to_folder(
        &mut self,
        conversation: &ConversationId,
        folder: &[u8; 16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let changed = self
            .store
            .move_conversation_to_folder(conversation, folder, rng)?;
        if changed {
            self.events.push_back(Event::FoldersChanged);
        }
        Ok(changed)
    }

    /// Idempotently move one exact typed conversation to virtual Unfiled.
    pub fn unfile_conversation(&mut self, conversation: &ConversationId) -> Result<bool> {
        let changed = self.store.unfile_conversation(conversation)?;
        if changed {
            self.events.push_back(Event::FoldersChanged);
        }
        Ok(changed)
    }

    /// Return the active folder for one exact available conversation.
    pub fn folder_for_conversation(
        &self,
        conversation: &ConversationId,
    ) -> Result<Option<FolderInfo>> {
        Ok(self
            .store
            .folder_for_conversation(conversation)?
            .map(folder_info))
    }

    /// List active available typed membership for one folder.
    pub fn folder_members(&self, folder: &[u8; 16]) -> Result<Vec<FolderConversationInfo>> {
        self.store
            .folder_members(folder)?
            .into_iter()
            .map(|conversation| self.folder_conversation_info(conversation))
            .collect()
    }

    /// Classify All/Unfiled/one folder, then independently apply label matching.
    pub fn folder_conversations(
        &self,
        selection: FolderSelection,
        selected_labels: &[[u8; 16]],
        label_mode: LabelMatchMode,
    ) -> Result<FolderConversationList> {
        let folder_result = self.store.folder_conversations(match selection {
            FolderSelection::All => StoreFolderSelection::All,
            FolderSelection::Unfiled => StoreFolderSelection::Unfiled,
            FolderSelection::Folder(folder) => StoreFolderSelection::Folder(folder),
        })?;
        let label_result = self.store.filter_label_conversations(
            selected_labels,
            match label_mode {
                LabelMatchMode::Any => LabelFilterMode::Any,
                LabelMatchMode::All => LabelFilterMode::All,
            },
        )?;
        let label_eligible = label_result
            .conversations
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(FolderConversationList {
            selection,
            selected_labels: label_result.selected,
            unavailable_labels: label_result.unavailable_selected,
            conversations: folder_result
                .conversations
                .into_iter()
                .filter(|conversation| label_eligible.contains(conversation))
                .map(|conversation| self.folder_conversation_info(conversation))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    /// Report stale local folder assignments without storage internals.
    pub fn stale_folder_assignments(&self) -> Result<Vec<StaleFolderInfo>> {
        Ok(self
            .store
            .stale_folder_assignments()?
            .into_iter()
            .map(|record| StaleFolderInfo {
                folder: record.folder,
                conversation: record.conversation,
                reason: match record.reason {
                    StoreStaleFolderReason::MissingFolder => NodeStaleFolderReason::MissingFolder,
                    StoreStaleFolderReason::UnavailableConversation => {
                        NodeStaleFolderReason::UnavailableConversation
                    }
                    StoreStaleFolderReason::MissingFolderAndConversation => {
                        NodeStaleFolderReason::MissingFolderAndConversation
                    }
                },
            })
            .collect())
    }

    /// Remove one exact folder assignment only while it remains stale.
    pub fn cleanup_stale_folder_assignment(
        &mut self,
        folder: &[u8; 16],
        conversation: &ConversationId,
    ) -> Result<bool> {
        let changed = self
            .store
            .cleanup_stale_folder_assignment(folder, conversation)?;
        if changed {
            self.events.push_back(Event::FoldersChanged);
        }
        Ok(changed)
    }

    fn folder_conversation_info(
        &self,
        conversation: ConversationId,
    ) -> Result<FolderConversationInfo> {
        let display_name = match &conversation {
            ConversationId::Peer(peer) => self.store.get_contact(peer)?.map(|contact| contact.name),
            ConversationId::Group(group) => self.store.get_group(group)?.map(|group| group.name),
            ConversationId::NoteToSelf => None,
        };
        Ok(FolderConversationInfo {
            conversation,
            display_name,
        })
    }
}

fn folder_info(folder: FolderRecord) -> FolderInfo {
    FolderInfo {
        id: folder.id,
        name: folder.name,
        order: folder.order,
    }
}
