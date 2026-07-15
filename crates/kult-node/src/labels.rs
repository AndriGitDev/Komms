//! B18 private local labels over the accepted F5 sealed metadata records.
//!
//! Every method in this module is local-only. It does not encode content,
//! inspect transports, enqueue envelopes, advertise capabilities, or alter
//! message/history state.

use rand_core::CryptoRngCore;

use kult_store::{
    render_label_color, ConversationId, LabelFilterMode, LabelRecord,
    StaleLabelReason as StoreStaleLabelReason,
};

use crate::{
    Event, LabelConversationInfo, LabelFilterInfo, LabelInfo, LabelMatchMode, Node,
    NodeStaleLabelReason, Result, StaleLabelInfo,
};

impl Node {
    /// Create a private label with a collision-safe cryptorandom stable id.
    pub fn create_label(
        &mut self,
        name: &str,
        color: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<LabelInfo> {
        let record = self.store.create_label(name, color, rng)?;
        let info = self.label_info(record)?;
        self.events.push_back(Event::LabelsChanged);
        Ok(info)
    }

    /// List render-safe label definitions in deterministic insertion order.
    pub fn labels(&self) -> Result<Vec<LabelInfo>> {
        Ok(self
            .store
            .labels()?
            .into_iter()
            .enumerate()
            .map(|(order, record)| label_info(record, order))
            .collect())
    }

    /// Get one render-safe label by its exact stable id.
    pub fn label(&self, id: &[u8; 16]) -> Result<LabelInfo> {
        let record = self
            .store
            .label(id)?
            .ok_or(kult_store::StoreError::UnknownLabel)?;
        self.label_info(record)
    }

    /// Rename and recolor a label without changing id, membership, or order.
    pub fn update_label(
        &mut self,
        id: &[u8; 16],
        name: &str,
        color: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<LabelInfo> {
        let before = self
            .store
            .label(id)?
            .ok_or(kult_store::StoreError::UnknownLabel)?;
        let changed = before.name != name || before.color != color;
        let record = self.store.update_label(id, name, color, rng)?;
        let info = self.label_info(record)?;
        if changed {
            self.events.push_back(Event::LabelsChanged);
        }
        Ok(info)
    }

    /// Count memberships before an explicit destructive deletion decision.
    pub fn label_delete_assignment_count(&self, id: &[u8; 16]) -> Result<usize> {
        Ok(self.store.label_assignment_count(id)?)
    }

    /// Atomically delete a label and cascade every membership locally.
    pub fn delete_label(&mut self, id: &[u8; 16]) -> Result<usize> {
        let deleted = self.store.delete_label(id)?;
        self.events.push_back(Event::LabelsChanged);
        Ok(deleted)
    }

    /// Idempotently apply one label to one exact typed conversation.
    pub fn assign_label(
        &mut self,
        label: &[u8; 16],
        conversation: &ConversationId,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let changed = self.store.assign_label(label, conversation, rng)?;
        if changed {
            self.events.push_back(Event::LabelsChanged);
        }
        Ok(changed)
    }

    /// Idempotently remove one exact membership, including a stale one.
    pub fn unassign_label(
        &mut self,
        label: &[u8; 16],
        conversation: &ConversationId,
    ) -> Result<bool> {
        let changed = self.store.unassign_label(label, conversation)?;
        if changed {
            self.events.push_back(Event::LabelsChanged);
        }
        Ok(changed)
    }

    /// List active typed conversation membership for one label.
    pub fn label_members(&self, label: &[u8; 16]) -> Result<Vec<LabelConversationInfo>> {
        self.store
            .label_members(label)?
            .into_iter()
            .map(|conversation| self.label_conversation_info(conversation))
            .collect()
    }

    /// List active labels for one exact available typed conversation.
    pub fn labels_for_conversation(&self, conversation: &ConversationId) -> Result<Vec<LabelInfo>> {
        let all = self.labels()?;
        let assigned = self.store.labels_for_conversation(conversation)?;
        Ok(assigned
            .into_iter()
            .filter_map(|record| all.iter().find(|label| label.id == record.id).cloned())
            .collect())
    }

    /// Report stale local memberships without sealed bytes or storage nonces.
    pub fn stale_label_assignments(&self) -> Result<Vec<StaleLabelInfo>> {
        Ok(self
            .store
            .stale_label_assignments()?
            .into_iter()
            .map(|record| StaleLabelInfo {
                label: record.label,
                conversation: record.conversation,
                reason: match record.reason {
                    StoreStaleLabelReason::MissingLabel => NodeStaleLabelReason::MissingLabel,
                    StoreStaleLabelReason::UnavailableConversation => {
                        NodeStaleLabelReason::UnavailableConversation
                    }
                    StoreStaleLabelReason::MissingLabelAndConversation => {
                        NodeStaleLabelReason::MissingLabelAndConversation
                    }
                },
            })
            .collect())
    }

    /// Remove one exact membership only while it remains stale.
    pub fn cleanup_stale_label_assignment(
        &mut self,
        label: &[u8; 16],
        conversation: &ConversationId,
    ) -> Result<bool> {
        let changed = self
            .store
            .cleanup_stale_label_assignment(label, conversation)?;
        if changed {
            self.events.push_back(Event::LabelsChanged);
        }
        Ok(changed)
    }

    /// Apply deterministic local any/all filtering to all eligible conversations.
    pub fn filter_label_conversations(
        &self,
        selected: &[[u8; 16]],
        mode: LabelMatchMode,
    ) -> Result<LabelFilterInfo> {
        let result = self.store.filter_label_conversations(
            selected,
            match mode {
                LabelMatchMode::Any => LabelFilterMode::Any,
                LabelMatchMode::All => LabelFilterMode::All,
            },
        )?;
        Ok(LabelFilterInfo {
            selected: result.selected,
            unavailable_selected: result.unavailable_selected,
            conversations: result
                .conversations
                .into_iter()
                .map(|conversation| self.label_conversation_info(conversation))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn label_info(&self, record: LabelRecord) -> Result<LabelInfo> {
        let order = self
            .store
            .labels()?
            .iter()
            .position(|label| label.id == record.id)
            .ok_or(kult_store::StoreError::UnknownLabel)?;
        Ok(label_info(record, order))
    }

    fn label_conversation_info(
        &self,
        conversation: ConversationId,
    ) -> Result<LabelConversationInfo> {
        let display_name = match &conversation {
            ConversationId::Peer(peer) => self.store.get_contact(peer)?.map(|contact| contact.name),
            ConversationId::Group(group) => self.store.get_group(group)?.map(|group| group.name),
            ConversationId::NoteToSelf => None,
        };
        Ok(LabelConversationInfo {
            conversation,
            display_name,
        })
    }
}

fn label_info(record: LabelRecord, order: usize) -> LabelInfo {
    LabelInfo {
        id: record.id,
        name: record.name,
        color: render_label_color(&record.color).to_owned(),
        order: u32::try_from(order).unwrap_or(u32::MAX),
    }
}
