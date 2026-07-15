//! B11 private local conversation pins over the accepted F5 `PinRecord`.
//!
//! Pins affect local presentation order only. These methods never encode
//! content, inspect transports, enqueue envelopes, advertise capabilities, or
//! alter messages, delivery, folders, labels, or history.

use rand_core::CryptoRngCore;

use kult_store::{
    ConversationId, FolderSelection as StoreFolderSelection, LabelFilterMode, PinStatusRecord,
};

use crate::{
    Event, FolderSelection, LabelMatchMode, Node, PinConversationInfo, PinConversationList,
    PinInfo, Result,
};

impl Node {
    /// Idempotently append one exact available conversation to the pin order.
    pub fn pin_conversation(
        &mut self,
        conversation: &ConversationId,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let changed = self.store.pin_conversation(conversation, rng)?;
        if changed {
            self.events.push_back(Event::PinsChanged);
        }
        Ok(changed)
    }

    /// Idempotently unpin one exact active or stale conversation target.
    pub fn unpin_conversation(&mut self, conversation: &ConversationId) -> Result<bool> {
        let changed = self.store.unpin_conversation(conversation)?;
        if changed {
            self.events.push_back(Event::PinsChanged);
        }
        Ok(changed)
    }

    /// Return the exact durable pin state for one target, when present.
    pub fn pin_state(&self, conversation: &ConversationId) -> Result<Option<PinInfo>> {
        self.store
            .pin_state(conversation)?
            .map(|status| self.pin_info(status))
            .transpose()
    }

    /// List every durable pin, including unavailable stale targets.
    pub fn pins(&self) -> Result<Vec<PinInfo>> {
        self.store
            .pins()?
            .into_iter()
            .map(|status| self.pin_info(status))
            .collect()
    }

    /// Atomically rewrite the explicit complete durable pin target order.
    pub fn reorder_pins(
        &mut self,
        ordered: &[ConversationId],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<PinInfo>> {
        let before = self
            .store
            .pins()?
            .into_iter()
            .map(|status| status.pin.conversation)
            .collect::<Vec<_>>();
        let pins = self
            .store
            .reorder_pins(ordered, rng)?
            .into_iter()
            .map(|status| self.pin_info(status))
            .collect::<Result<Vec<_>>>()?;
        if before != ordered {
            self.events.push_back(Event::PinsChanged);
        }
        Ok(pins)
    }

    /// List only unavailable durable pins for explicit diagnosis/cleanup.
    pub fn stale_pins(&self) -> Result<Vec<PinInfo>> {
        self.store
            .pins()?
            .into_iter()
            .filter(|status| !status.active)
            .map(|status| self.pin_info(status))
            .collect()
    }

    /// Remove one exact pin only while its conversation remains unavailable.
    pub fn cleanup_stale_pin(&mut self, conversation: &ConversationId) -> Result<bool> {
        let changed = self.store.cleanup_stale_pin(conversation)?;
        if changed {
            self.events.push_back(Event::PinsChanged);
        }
        Ok(changed)
    }

    /// Classify by folder, filter by labels, then apply pin/activity ordering.
    pub fn pin_conversations(
        &self,
        selection: FolderSelection,
        selected_labels: &[[u8; 16]],
        label_mode: LabelMatchMode,
    ) -> Result<PinConversationList> {
        let result = self.store.pin_conversations(
            match selection {
                FolderSelection::All => StoreFolderSelection::All,
                FolderSelection::Unfiled => StoreFolderSelection::Unfiled,
                FolderSelection::Folder(folder) => StoreFolderSelection::Folder(folder),
            },
            selected_labels,
            match label_mode {
                LabelMatchMode::Any => LabelFilterMode::Any,
                LabelMatchMode::All => LabelFilterMode::All,
            },
        )?;
        Ok(PinConversationList {
            selection,
            selected_labels: result.selected_labels,
            unavailable_labels: result.unavailable_labels,
            conversations: result
                .conversations
                .into_iter()
                .map(|record| {
                    Ok(PinConversationInfo {
                        display_name: self.conversation_display_name(&record.conversation)?,
                        pinned: record.pin_order.is_some(),
                        pin_order: record.pin_order,
                        recent_activity: record.recent_activity,
                        conversation: record.conversation,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn pin_info(&self, status: PinStatusRecord) -> Result<PinInfo> {
        Ok(PinInfo {
            display_name: if status.active {
                self.conversation_display_name(&status.pin.conversation)?
            } else {
                None
            },
            conversation: status.pin.conversation,
            order: status.pin.order,
            active: status.active,
        })
    }

    fn conversation_display_name(&self, conversation: &ConversationId) -> Result<Option<String>> {
        match conversation {
            ConversationId::Peer(peer) => {
                Ok(self.store.get_contact(peer)?.map(|contact| contact.name))
            }
            ConversationId::Group(group) => {
                Ok(self.store.get_group(group)?.map(|group| group.name))
            }
            ConversationId::NoteToSelf => Ok(None),
        }
    }
}
