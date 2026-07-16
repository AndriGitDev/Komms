//! Derived immutable edit history (ADR-0020).

use kult_protocol::{decode_content, encode_text, DecodedContent};
use kult_store::{Direction, GroupMessageRecord, MessageRecord};

use crate::api::{EditVersionInfo, ResolvedGroupMessage, ResolvedMessage};

/// Maximum locally authored immutable edits per exact target.
pub const MAX_MESSAGE_EDITS: usize = 64;

struct PairwiseEdit {
    direction: Direction,
    peer: [u8; 32],
    id: [u8; 16],
    target_author: [u8; 32],
    target_content_id: [u8; 16],
    revision: u64,
    timestamp: u64,
    body: String,
}

struct GroupEdit {
    sender: [u8; 32],
    id: [u8; 16],
    target_author: [u8; 32],
    target_content_id: [u8; 16],
    revision: u64,
    timestamp: u64,
    body: String,
}

pub(crate) fn resolve_pairwise(
    records: Vec<MessageRecord>,
    local_peer: [u8; 32],
) -> Vec<ResolvedMessage> {
    let edits = records
        .iter()
        .filter_map(|record| match decode_content(&record.body) {
            DecodedContent::Edit { id, edit } => Some(PairwiseEdit {
                direction: record.direction,
                peer: record.peer,
                id,
                target_author: edit.target_author,
                target_content_id: edit.target_content_id,
                revision: edit.revision,
                timestamp: record.timestamp,
                body: edit.text.to_owned(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    records
        .into_iter()
        .filter_map(|mut record| {
            let (content_id, original) = match decode_content(&record.body) {
                DecodedContent::Edit { .. } => return None,
                DecodedContent::Text { id, text } => (Some(id), Some(text.to_owned())),
                _ => (None, None),
            };
            let Some(target_content_id) = content_id else {
                return Some(ResolvedMessage {
                    record,
                    edited: false,
                    winning_revision: 0,
                    versions: Vec::new(),
                });
            };
            let target_author = match record.direction {
                Direction::Outbound => local_peer,
                Direction::Inbound => record.peer,
            };
            let mut versions = vec![EditVersionInfo {
                id: target_content_id,
                revision: 0,
                timestamp: record.timestamp,
                body: original.expect("canonical Text has UTF-8"),
            }];
            for edit in &edits {
                let event_author = match edit.direction {
                    Direction::Outbound => local_peer,
                    Direction::Inbound => edit.peer,
                };
                if event_author == target_author
                    && edit.target_author == target_author
                    && edit.target_content_id == target_content_id
                {
                    versions.push(EditVersionInfo {
                        id: edit.id,
                        revision: edit.revision,
                        timestamp: edit.timestamp,
                        body: edit.body.clone(),
                    });
                }
            }
            versions[1..].sort_by_key(|version| (version.revision, version.id));
            let winner = versions.last().expect("original version exists");
            let edited = winner.revision > 0;
            if edited {
                record.body = encode_text(target_content_id, &winner.body)
                    .expect("accepted edit text is bounded canonical UTF-8");
            }
            Some(ResolvedMessage {
                record,
                edited,
                winning_revision: winner.revision,
                versions,
            })
        })
        .collect()
}

pub(crate) fn resolve_group(records: Vec<GroupMessageRecord>) -> Vec<ResolvedGroupMessage> {
    let edits = records
        .iter()
        .filter_map(|record| match decode_content(&record.body) {
            DecodedContent::Edit { id, edit } => Some(GroupEdit {
                sender: record.sender,
                id,
                target_author: edit.target_author,
                target_content_id: edit.target_content_id,
                revision: edit.revision,
                timestamp: record.timestamp,
                body: edit.text.to_owned(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    records
        .into_iter()
        .filter_map(|mut record| {
            let (content_id, original) = match decode_content(&record.body) {
                DecodedContent::Edit { .. } => return None,
                DecodedContent::Text { id, text } => (Some(id), Some(text.to_owned())),
                _ => (None, None),
            };
            let Some(target_content_id) = content_id else {
                return Some(ResolvedGroupMessage {
                    record,
                    edited: false,
                    winning_revision: 0,
                    versions: Vec::new(),
                });
            };
            let target_author = record.sender;
            let mut versions = vec![EditVersionInfo {
                id: target_content_id,
                revision: 0,
                timestamp: record.timestamp,
                body: original.expect("canonical Text has UTF-8"),
            }];
            for edit in &edits {
                if edit.sender == target_author
                    && edit.target_author == target_author
                    && edit.target_content_id == target_content_id
                {
                    versions.push(EditVersionInfo {
                        id: edit.id,
                        revision: edit.revision,
                        timestamp: edit.timestamp,
                        body: edit.body.clone(),
                    });
                }
            }
            versions[1..].sort_by_key(|version| (version.revision, version.id));
            let winner = versions.last().expect("original version exists");
            let edited = winner.revision > 0;
            if edited {
                record.body = encode_text(target_content_id, &winner.body)
                    .expect("accepted edit text is bounded canonical UTF-8");
            }
            Some(ResolvedGroupMessage {
                record,
                edited,
                winning_revision: winner.revision,
                versions,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_protocol::{encode_edit, Edit};
    use kult_store::DeliveryState;

    const ME: [u8; 32] = [0x11; 32];
    const PEER: [u8; 32] = [0x22; 32];
    const GROUP: [u8; 32] = [0x33; 32];
    const TARGET: [u8; 16] = [0x44; 16];

    fn pair(id: [u8; 16], direction: Direction, timestamp: u64, body: Vec<u8>) -> MessageRecord {
        MessageRecord {
            id,
            peer: PEER,
            direction,
            state: if direction == Direction::Inbound {
                DeliveryState::Received
            } else {
                DeliveryState::Delivered
            },
            timestamp,
            body,
            wire_id: None,
        }
    }

    fn group(
        id: [u8; 16],
        sender: [u8; 32],
        direction: Direction,
        timestamp: u64,
        body: Vec<u8>,
    ) -> GroupMessageRecord {
        GroupMessageRecord {
            id,
            group: GROUP,
            sender,
            direction,
            timestamp,
            body,
            deliveries: Vec::new(),
            wire_body: None,
        }
    }

    fn edit(id: [u8; 16], author: [u8; 32], revision: u64, text: &str) -> Vec<u8> {
        encode_edit(
            id,
            &Edit {
                target_author: author,
                target_content_id: TARGET,
                revision,
                text,
            },
        )
        .unwrap()
    }

    #[test]
    fn pairwise_resolution_is_authorized_order_independent_and_hides_events() {
        let low = [0x01; 16];
        let tie_winner = [0xfe; 16];
        let wrong_author = [0xff; 16];
        let records = vec![
            pair(low, Direction::Inbound, 1, edit(low, PEER, 2, "low")),
            pair(
                wrong_author,
                Direction::Inbound,
                2,
                edit(wrong_author, ME, 99, "forged"),
            ),
            pair(
                tie_winner,
                Direction::Inbound,
                3,
                edit(tie_winner, PEER, 2, "winner"),
            ),
            pair(
                TARGET,
                Direction::Inbound,
                4,
                encode_text(TARGET, "original").unwrap(),
            ),
        ];
        let resolved = resolve_pairwise(records.clone(), ME);
        assert_eq!(resolved.len(), 1, "every Edit event is hidden");
        assert!(resolved[0].edited);
        assert_eq!(resolved[0].winning_revision, 2);
        assert!(matches!(
            decode_content(&resolved[0].record.body),
            DecodedContent::Text {
                id: TARGET,
                text: "winner"
            }
        ));
        assert_eq!(
            resolved[0]
                .versions
                .iter()
                .map(|version| (version.revision, version.id, version.body.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, TARGET, "original"),
                (2, low, "low"),
                (2, tie_winner, "winner"),
            ]
        );

        let mut reversed = records;
        reversed.reverse();
        let reordered = resolve_pairwise(reversed, ME);
        assert_eq!(reordered[0].winning_revision, 2);
        assert_eq!(reordered[0].record.body, resolved[0].record.body);
        assert_eq!(reordered[0].versions, resolved[0].versions);
    }

    #[test]
    fn group_resolution_rejects_cross_author_and_wrong_kind_targets() {
        let valid = [0x55; 16];
        let forged = [0x66; 16];
        let mention_like_target = [0x77; 16];
        let records = vec![
            group(
                valid,
                PEER,
                Direction::Inbound,
                1,
                edit(valid, PEER, 1, "group edit"),
            ),
            group(
                forged,
                ME,
                Direction::Inbound,
                2,
                edit(forged, PEER, 100, "cross author"),
            ),
            group(
                TARGET,
                PEER,
                Direction::Inbound,
                3,
                encode_text(TARGET, "group original").unwrap(),
            ),
            group(
                mention_like_target,
                PEER,
                Direction::Inbound,
                4,
                b"legacy has no content id".to_vec(),
            ),
        ];
        let resolved = resolve_group(records);
        assert_eq!(resolved.len(), 2);
        let text = resolved
            .iter()
            .find(|message| message.record.id == TARGET)
            .unwrap();
        assert!(text.edited);
        assert_eq!(text.versions.len(), 2);
        assert!(matches!(
            decode_content(&text.record.body),
            DecodedContent::Text {
                text: "group edit",
                ..
            }
        ));
        let legacy = resolved
            .iter()
            .find(|message| message.record.id == mention_like_target)
            .unwrap();
        assert!(!legacy.edited);
        assert!(legacy.versions.is_empty());
    }

    #[test]
    fn shared_parity_fixture_converges_for_every_arrival_order() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/c3-message-edit-parity.json"
        ))
        .unwrap();
        let case = &fixture["case"];
        let target = hex_array::<16>(case["target_content_id"].as_str().unwrap());
        assert_eq!(target, TARGET);
        let expected = case["expected_versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|version| {
                (
                    hex_array::<16>(version["id"].as_str().unwrap()),
                    version["revision"].as_u64().unwrap(),
                    version["text"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();

        for order in case["arrival_orders"].as_array().unwrap() {
            let records = order
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let name = name.as_str().unwrap();
                    if name == "original" {
                        return pair(
                            target,
                            Direction::Outbound,
                            index as u64,
                            encode_text(target, case["original"].as_str().unwrap()).unwrap(),
                        );
                    }
                    let event = case["events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|event| event["name"].as_str() == Some(name))
                        .unwrap();
                    let id = hex_array::<16>(event["id"].as_str().unwrap());
                    pair(
                        id,
                        Direction::Outbound,
                        index as u64,
                        encode_edit(
                            id,
                            &Edit {
                                target_author: hex_array::<32>(event["author"].as_str().unwrap()),
                                target_content_id: target,
                                revision: event["revision"].as_u64().unwrap(),
                                text: event["text"].as_str().unwrap(),
                            },
                        )
                        .unwrap(),
                    )
                })
                .collect();
            let resolved = resolve_pairwise(records, ME);
            assert_eq!(resolved.len(), 1);
            assert_eq!(
                resolved[0]
                    .versions
                    .iter()
                    .map(|version| (version.id, version.revision, version.body.as_str()))
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                resolved[0].winning_revision,
                case["winning_revision"].as_u64().unwrap()
            );
            assert!(matches!(
                decode_content(&resolved[0].record.body),
                DecodedContent::Text { text, .. }
                    if text == case["winning_text"].as_str().unwrap()
            ));
        }
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut bytes = [0u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }
}
