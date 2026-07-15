//! Command-line client for a running `kultd`. Speaks the newline-delimited
//! JSON RPC protocol over the daemon's Unix socket (synchronously — one
//! request, one response; `watch` streams events until interrupted).

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use serde_json::{json, Value};

const USAGE: &str = "\
kult — client for a running kultd

USAGE:
    kult [--socket PATH] COMMAND [ARGS]

The socket defaults to the KULTD_SOCKET environment variable.

COMMANDS:
    status                          daemon and node status
    bundle                          export a fresh prekey bundle (hex)
    add-contact NAME BUNDLE_HEX [--hint MULTIADDR]... [--relay MULTIADDR]...
                                [--mesh NODE|broadcast]...
                                    add a contact from an out-of-band bundle
    add NAME ADDRESS                add a contact from a kult address (DHT)
    send PEER_HEX TEXT...           queue a message
    attachment-send PEER_HEX PATH MEDIA_TYPE [FILENAME]
                                    import and queue a pairwise attachment
    attachment-send-preview PEER_HEX PATH MEDIA_TYPE PREVIEW_PATH PREVIEW_MEDIA_TYPE [FILENAME]
                                    import pairwise content plus a sealed preview
    group-attachment-send GROUP_HEX PATH MEDIA_TYPE [FILENAME]
                                    import and queue a group attachment
    group-attachment-send-preview GROUP_HEX PATH MEDIA_TYPE PREVIEW_PATH PREVIEW_MEDIA_TYPE [FILENAME]
                                    import group content plus a sealed preview
    attachments                     list render-safe attachment transfers
    attachment-accept TRANSFER_HEX  accept an inbound offer
    attachment-reject TRANSFER_HEX  reject an inbound offer
    attachment-cancel TRANSFER_HEX  cancel transfer activity
    attachment-pause TRANSFER_HEX   pause and retain verified progress
    attachment-resume TRANSFER_HEX  resume a paused transfer
    attachment-export TRANSFER_HEX PATH
                                    stream a completed object to a new file
    attachment-preview-export TRANSFER_HEX PATH
                                    stream a sealed preview to a new file
    schedule PEER_HEX UNIX_SECS TEXT... schedule pairwise text at a UTC instant
    group-schedule GROUP_HEX UNIX_SECS TEXT... schedule group text
    scheduled                       list scheduled messages
    schedule-edit ID UNIX_SECS TEXT... edit a scheduled message
    schedule-cancel ID              cancel a scheduled message
    note TEXT...                    append to the local note-to-self conversation
    note-messages                   local note-to-self history
    folder-create NAME...           create a private local folder
    folders                         list folders in deterministic manual order
    folder-get FOLDER_ID            get one folder by 32-hex-character id
    folder-rename FOLDER_ID NAME... rename without changing order or membership
    folder-reorder FOLDER_ID...     atomically set the complete active id order
    folder-delete FOLDER_ID [--yes] preview assignment count and confirm deletion;
                                    automation must pass --yes
    folder-move FOLDER_ID TARGET    move peer:HEX, group:HEX, or note-to-self
    folder-unfile TARGET            move one typed conversation to Unfiled
    folder-membership FOLDER_ID     list active typed members
    conversation-folder TARGET      get one typed conversation's active folder
    folder-conversations all|unfiled|FOLDER_ID [any|all [LABEL_ID]...]
                                    list folder selection, then apply label filter
    folder-stale                    inspect render-safe stale assignments
    folder-stale-cleanup FOLDER_ID TARGET
                                    remove one exact assignment only if stale
    label-create COLOR NAME...      create a private label; prints its stable id
    labels                          list labels in stable local order
    label-get LABEL_ID              get one label by 32-hex-character id
    label-update LABEL_ID COLOR NAME...
                                    rename/recolor without changing membership
    label-delete LABEL_ID [--yes]   preview assignment count and confirm deletion;
                                    automation must pass --yes
    label-assign LABEL_ID TARGET    idempotently assign to peer:HEX, group:HEX,
                                    or note-to-self
    label-unassign LABEL_ID TARGET  idempotently remove exact membership
    label-membership LABEL_ID       list active typed targets for one label
    labels-for TARGET               list active labels for one typed target
    label-stale                     inspect render-safe stale memberships
    label-stale-cleanup LABEL_ID TARGET
                                    remove one exact membership only if stale
    label-filter any|all [LABEL_ID]...
                                    filter eligible conversations locally
    pin TARGET                      pin peer:HEX, group:HEX, or note-to-self
    unpin TARGET                    idempotently remove one exact pin
    pin-state TARGET                inspect one typed conversation's pin state
    pins                            list durable pins, including stale entries
    pin-reorder TARGET...           atomically set the complete durable pin order
    pin-stale                       inspect render-safe unavailable pins
    pin-stale-cleanup TARGET        remove one exact pin only if unavailable
    pin-conversations all|unfiled|FOLDER_ID [any|all [LABEL_ID]...]
                                    compose folder, label, then pin ordering
    group-create NAME [MEMBER_HEX]... create a sender-key group
    group-send GROUP_HEX TEXT...     queue a group message
    group-mention-capability GROUP_HEX
                                    review exact current member support
    group-mention-send GROUP_HEX REVIEW_TOKEN TEXT START:END:PEER_HEX...
                                    send quoted exact text with explicit UTF-8 byte spans
    group-add GROUP_HEX PEER_HEX     add a member (creator only)
    group-remove GROUP_HEX PEER_HEX  remove a member (creator only)
    group-leave GROUP_HEX            leave a group
    groups                            list groups
    group-messages GROUP_HEX         group message history
    contacts                        list contacts
    carriers                        list per-peer carrier capability snapshots
    messages PEER_HEX               message history with a peer
    safety PEER_HEX                 safety number for out-of-band verification
    verify PEER_HEX                 mark a contact verified
    set-hints PEER_HEX [--hint MULTIADDR]... [--relay MULTIADDR]...
                       [--mesh NODE|broadcast]...
                                    replace a contact's delivery hints
    publish                         publish the prekey bundle on the DHT now
    backup PATH                     write an encrypted backup file and print the
                                    one-time 24-word mnemonic that seals it
                                    (write it down; it is shown exactly once)
    watch                           stream events until interrupted
    -h, --help                      this text
";

/// Collect `--hint`/`--relay`/`--mesh` pairs from the remaining arguments.
fn parse_hints(args: &[String]) -> Result<Vec<Value>, String> {
    let mut hints = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?.to_owned();
        match flag.as_str() {
            "--hint" => hints.push(json!({ "multiaddr": value })),
            "--relay" => hints.push(json!({ "relay": value })),
            "--mesh" => {
                // "broadcast" floods the whole mesh — the normal mode;
                // recipients recognize their envelopes by delivery token.
                let node: u32 = if value == "broadcast" {
                    u32::MAX
                } else {
                    value.parse().map_err(|_| "bad --mesh node number")?
                };
                hints.push(json!({ "mesh": node }));
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(hints)
}

fn parse_mention_span(value: &str) -> Result<Value, String> {
    let mut parts = value.splitn(3, ':');
    let start = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| "mention span start must be a u32 byte offset".to_owned())?;
    let end = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .ok_or_else(|| "mention span end must be a u32 byte offset".to_owned())?;
    let target = parts
        .next()
        .filter(|peer| peer.len() == 64 && peer.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "mention span target must be a 64-character hex peer id".to_owned())?;
    Ok(json!({ "start": start, "end": end, "target": target }))
}

const LABEL_COLORS: [&str; 9] = [
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
];

fn parse_label_id(value: &str) -> Result<String, String> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("label id must be 32 hexadecimal characters".to_owned())
    }
}

fn parse_folder_id(value: &str) -> Result<String, String> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("folder id must be 32 hexadecimal characters".to_owned())
    }
}

fn validate_folder_write(name: &str) -> Result<(), String> {
    let pattern_white_space = |value: char| {
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
    };
    if name.is_empty() || name.len() > 256 || name.chars().all(pattern_white_space) {
        Err("invalid folder name".to_owned())
    } else {
        Ok(())
    }
}

fn parse_label_target(value: &str) -> Result<Value, String> {
    if value == "note-to-self" {
        return Ok(json!({ "type": "note_to_self" }));
    }
    let (kind, id) = value
        .split_once(':')
        .ok_or_else(|| "target must be peer:HEX, group:HEX, or note-to-self".to_owned())?;
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("target id must be 64 hexadecimal characters".to_owned());
    }
    match kind {
        "peer" => Ok(json!({ "type": "peer", "id": id.to_ascii_lowercase() })),
        "group" => Ok(json!({ "type": "group", "id": id.to_ascii_lowercase() })),
        _ => Err("target must be peer:HEX, group:HEX, or note-to-self".to_owned()),
    }
}

fn validate_label_write(name: &str, color: &str) -> Result<(), String> {
    let pattern_white_space = |value: char| {
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
    };
    if name.is_empty() || name.len() > 256 || name.chars().all(pattern_white_space) {
        return Err("invalid label name".to_owned());
    }
    if !LABEL_COLORS.contains(&color) {
        return Err("unsupported label color".to_owned());
    }
    Ok(())
}

fn build_request(command: &str, args: &[String]) -> Result<Value, String> {
    let need = |n: usize| -> Result<(), String> {
        if args.len() < n {
            Err(format!("{command}: missing arguments\n\n{USAGE}"))
        } else {
            Ok(())
        }
    };
    let request = match command {
        "status" => json!({ "op": "status" }),
        "bundle" => json!({ "op": "bundle" }),
        "add-contact" => {
            need(2)?;
            json!({
                "op": "add_contact",
                "name": args[0],
                "bundle": args[1],
                "hints": parse_hints(&args[2..])?,
            })
        }
        "add" => {
            need(2)?;
            json!({ "op": "add_by_address", "name": args[0], "address": args[1] })
        }
        "send" => {
            need(2)?;
            json!({ "op": "send", "peer": args[0], "body": args[1..].join(" ") })
        }
        "attachment-send" => {
            need(3)?;
            if args.len() > 4 {
                return Err("attachment-send: too many arguments".to_owned());
            }
            json!({
                "op": "attachment_send",
                "peer": args[0],
                "path": args[1],
                "media_type": args[2],
                "filename": args.get(3),
            })
        }
        "attachment-send-preview" => {
            need(5)?;
            if args.len() > 6 {
                return Err("attachment-send-preview: too many arguments".to_owned());
            }
            json!({
                "op": "attachment_send",
                "peer": args[0],
                "path": args[1],
                "media_type": args[2],
                "preview_path": args[3],
                "preview_media_type": args[4],
                "filename": args.get(5),
            })
        }
        "group-attachment-send" => {
            need(3)?;
            if args.len() > 4 {
                return Err("group-attachment-send: too many arguments".to_owned());
            }
            json!({
                "op": "group_attachment_send",
                "group": args[0],
                "path": args[1],
                "media_type": args[2],
                "filename": args.get(3),
            })
        }
        "group-attachment-send-preview" => {
            need(5)?;
            if args.len() > 6 {
                return Err("group-attachment-send-preview: too many arguments".to_owned());
            }
            json!({
                "op": "group_attachment_send",
                "group": args[0],
                "path": args[1],
                "media_type": args[2],
                "preview_path": args[3],
                "preview_media_type": args[4],
                "filename": args.get(5),
            })
        }
        "attachments" => json!({ "op": "attachments" }),
        "attachment-accept" => {
            need(1)?;
            json!({ "op": "attachment_accept", "transfer": args[0] })
        }
        "attachment-reject" => {
            need(1)?;
            json!({ "op": "attachment_reject", "transfer": args[0] })
        }
        "attachment-cancel" => {
            need(1)?;
            json!({ "op": "attachment_cancel", "transfer": args[0] })
        }
        "attachment-pause" => {
            need(1)?;
            json!({ "op": "attachment_pause", "transfer": args[0] })
        }
        "attachment-resume" => {
            need(1)?;
            json!({ "op": "attachment_resume", "transfer": args[0] })
        }
        "attachment-export" => {
            need(2)?;
            json!({ "op": "attachment_export", "transfer": args[0], "path": args[1] })
        }
        "attachment-preview-export" => {
            need(2)?;
            json!({
                "op": "attachment_export",
                "transfer": args[0],
                "path": args[1],
                "preview": true,
            })
        }
        "schedule" => {
            need(3)?;
            let not_before: u64 = args[1]
                .parse()
                .map_err(|_| "schedule: UNIX_SECS must be an unsigned integer")?;
            json!({
                "op": "schedule",
                "peer": args[0],
                "not_before": not_before,
                "body": args[2..].join(" "),
            })
        }
        "group-schedule" => {
            need(3)?;
            let not_before: u64 = args[1]
                .parse()
                .map_err(|_| "group-schedule: UNIX_SECS must be an unsigned integer")?;
            json!({
                "op": "group_schedule",
                "group": args[0],
                "not_before": not_before,
                "body": args[2..].join(" "),
            })
        }
        "scheduled" => json!({ "op": "scheduled_messages" }),
        "schedule-edit" => {
            need(3)?;
            let not_before: u64 = args[1]
                .parse()
                .map_err(|_| "schedule-edit: UNIX_SECS must be an unsigned integer")?;
            json!({
                "op": "scheduled_edit",
                "message": args[0],
                "not_before": not_before,
                "body": args[2..].join(" "),
            })
        }
        "schedule-cancel" => {
            need(1)?;
            json!({ "op": "scheduled_cancel", "message": args[0] })
        }
        "note" => {
            need(1)?;
            json!({ "op": "note_to_self_send", "body": args.join(" ") })
        }
        "note-messages" => json!({ "op": "note_to_self_messages" }),
        "folder-create" => {
            need(1)?;
            let name = args.join(" ");
            validate_folder_write(&name)?;
            json!({ "op": "folder_create", "name": name })
        }
        "folders" => {
            if !args.is_empty() {
                return Err("folders: too many arguments".to_owned());
            }
            json!({ "op": "folders" })
        }
        "folder-get" => {
            need(1)?;
            if args.len() != 1 {
                return Err("folder-get: too many arguments".to_owned());
            }
            json!({ "op": "folder_get", "folder": parse_folder_id(&args[0])? })
        }
        "folder-rename" => {
            need(2)?;
            let folder = parse_folder_id(&args[0])?;
            let name = args[1..].join(" ");
            validate_folder_write(&name)?;
            json!({ "op": "folder_rename", "folder": folder, "name": name })
        }
        "folder-reorder" => {
            if args.len() > 128 {
                return Err("folder-reorder accepts at most 128 ids".to_owned());
            }
            let folders = args
                .iter()
                .map(|id| parse_folder_id(id))
                .collect::<Result<Vec<_>, _>>()?;
            json!({ "op": "folder_reorder", "folders": folders })
        }
        "folder-delete" => {
            need(1)?;
            if args.len() > 2 || (args.len() == 2 && args[1] != "--yes") {
                return Err("folder-delete: expected FOLDER_ID [--yes]".to_owned());
            }
            json!({
                "op": "folder_delete",
                "folder": parse_folder_id(&args[0])?,
                "confirm": args.get(1).map(String::as_str) == Some("--yes"),
            })
        }
        "folder-move" => {
            need(2)?;
            if args.len() != 2 {
                return Err("folder-move: too many arguments".to_owned());
            }
            json!({
                "op": "folder_move",
                "folder": parse_folder_id(&args[0])?,
                "target": parse_label_target(&args[1])?,
            })
        }
        "folder-unfile" => {
            need(1)?;
            if args.len() != 1 {
                return Err("folder-unfile: too many arguments".to_owned());
            }
            json!({ "op": "folder_unfile", "target": parse_label_target(&args[0])? })
        }
        "folder-membership" => {
            need(1)?;
            if args.len() != 1 {
                return Err("folder-membership: too many arguments".to_owned());
            }
            json!({ "op": "folder_membership", "folder": parse_folder_id(&args[0])? })
        }
        "conversation-folder" => {
            need(1)?;
            if args.len() != 1 {
                return Err("conversation-folder: too many arguments".to_owned());
            }
            json!({ "op": "conversation_folder", "target": parse_label_target(&args[0])? })
        }
        "folder-conversations" => {
            need(1)?;
            let selection = match args[0].as_str() {
                "all" => json!({ "type": "all" }),
                "unfiled" => json!({ "type": "unfiled" }),
                id => json!({ "type": "folder", "id": parse_folder_id(id)? }),
            };
            let (mode, label_args) = match args.get(1).map(String::as_str) {
                None => ("any", &args[1..]),
                Some("any") => ("any", &args[2..]),
                Some("all") => ("all", &args[2..]),
                Some(_) => {
                    return Err("folder-conversations label mode must be any or all".to_owned())
                }
            };
            if label_args.len() > 128 {
                return Err("folder-conversations accepts at most 128 label ids".to_owned());
            }
            let labels = label_args
                .iter()
                .map(|id| parse_label_id(id))
                .collect::<Result<Vec<_>, _>>()?;
            json!({ "op": "folder_conversations", "selection": selection, "mode": mode, "labels": labels })
        }
        "folder-stale" => {
            if !args.is_empty() {
                return Err("folder-stale: too many arguments".to_owned());
            }
            json!({ "op": "folder_stale" })
        }
        "folder-stale-cleanup" => {
            need(2)?;
            if args.len() != 2 {
                return Err("folder-stale-cleanup: too many arguments".to_owned());
            }
            json!({
                "op": "folder_stale_cleanup",
                "folder": parse_folder_id(&args[0])?,
                "target": parse_label_target(&args[1])?,
            })
        }
        "label-create" => {
            need(2)?;
            let color = &args[0];
            let name = args[1..].join(" ");
            validate_label_write(&name, color)?;
            json!({ "op": "label_create", "name": name, "color": color })
        }
        "labels" => {
            if !args.is_empty() {
                return Err("labels: too many arguments".to_owned());
            }
            json!({ "op": "labels" })
        }
        "label-get" => {
            need(1)?;
            if args.len() != 1 {
                return Err("label-get: too many arguments".to_owned());
            }
            json!({ "op": "label_get", "label": parse_label_id(&args[0])? })
        }
        "label-update" => {
            need(3)?;
            let label = parse_label_id(&args[0])?;
            let color = &args[1];
            let name = args[2..].join(" ");
            validate_label_write(&name, color)?;
            json!({ "op": "label_update", "label": label, "name": name, "color": color })
        }
        "label-delete" => {
            need(1)?;
            if args.len() > 2 || (args.len() == 2 && args[1] != "--yes") {
                return Err("label-delete: expected LABEL_ID [--yes]".to_owned());
            }
            json!({
                "op": "label_delete",
                "label": parse_label_id(&args[0])?,
                "confirm": args.get(1).map(String::as_str) == Some("--yes"),
            })
        }
        "label-assign" | "label-unassign" => {
            need(2)?;
            if args.len() != 2 {
                return Err(format!("{command}: too many arguments"));
            }
            json!({
                "op": if command == "label-assign" { "label_assign" } else { "label_unassign" },
                "label": parse_label_id(&args[0])?,
                "target": parse_label_target(&args[1])?,
            })
        }
        "label-membership" => {
            need(1)?;
            if args.len() != 1 {
                return Err("label-membership: too many arguments".to_owned());
            }
            json!({ "op": "label_membership", "label": parse_label_id(&args[0])? })
        }
        "labels-for" => {
            need(1)?;
            if args.len() != 1 {
                return Err("labels-for: too many arguments".to_owned());
            }
            json!({ "op": "labels_for_conversation", "target": parse_label_target(&args[0])? })
        }
        "label-stale" => {
            if !args.is_empty() {
                return Err("label-stale: too many arguments".to_owned());
            }
            json!({ "op": "label_stale" })
        }
        "label-stale-cleanup" => {
            need(2)?;
            if args.len() != 2 {
                return Err("label-stale-cleanup: too many arguments".to_owned());
            }
            json!({
                "op": "label_stale_cleanup",
                "label": parse_label_id(&args[0])?,
                "target": parse_label_target(&args[1])?,
            })
        }
        "label-filter" => {
            need(1)?;
            if args.len() > 129 {
                return Err("label-filter accepts at most 128 ids".to_owned());
            }
            if args[0] != "any" && args[0] != "all" {
                return Err("label-filter mode must be any or all".to_owned());
            }
            let labels = args[1..]
                .iter()
                .map(|id| parse_label_id(id))
                .collect::<Result<Vec<_>, _>>()?;
            json!({ "op": "label_filter", "mode": args[0], "labels": labels })
        }
        "pin" | "unpin" | "pin-state" | "pin-stale-cleanup" => {
            need(1)?;
            if args.len() != 1 {
                return Err(format!("{command}: too many arguments"));
            }
            let op = match command {
                "pin" => "pin",
                "unpin" => "unpin",
                "pin-state" => "pin_state",
                "pin-stale-cleanup" => "pin_stale_cleanup",
                _ => unreachable!(),
            };
            json!({ "op": op, "target": parse_label_target(&args[0])? })
        }
        "pins" | "pin-stale" => {
            if !args.is_empty() {
                return Err(format!("{command}: too many arguments"));
            }
            json!({ "op": if command == "pins" { "pins" } else { "pin_stale" } })
        }
        "pin-reorder" => {
            if args.len() > 8192 {
                return Err("pin-reorder accepts at most 8192 targets".to_owned());
            }
            let targets = args
                .iter()
                .map(|target| parse_label_target(target))
                .collect::<Result<Vec<_>, _>>()?;
            json!({ "op": "pin_reorder", "targets": targets })
        }
        "pin-conversations" => {
            need(1)?;
            let selection = match args[0].as_str() {
                "all" => json!({ "type": "all" }),
                "unfiled" => json!({ "type": "unfiled" }),
                id => json!({ "type": "folder", "id": parse_folder_id(id)? }),
            };
            let (mode, label_args) = match args.get(1).map(String::as_str) {
                None => ("any", &args[1..]),
                Some("any") => ("any", &args[2..]),
                Some("all") => ("all", &args[2..]),
                Some(_) => return Err("pin-conversations label mode must be any or all".to_owned()),
            };
            if label_args.len() > 128 {
                return Err("pin-conversations accepts at most 128 label ids".to_owned());
            }
            let labels = label_args
                .iter()
                .map(|id| parse_label_id(id))
                .collect::<Result<Vec<_>, _>>()?;
            json!({ "op": "pin_conversations", "selection": selection, "mode": mode, "labels": labels })
        }
        "group-create" => {
            need(1)?;
            json!({ "op": "group_create", "name": args[0], "members": args[1..] })
        }
        "group-send" => {
            need(2)?;
            json!({ "op": "group_send", "group": args[0], "body": args[1..].join(" ") })
        }
        "group-mention-capability" => {
            need(1)?;
            if args.len() != 1 {
                return Err("group-mention-capability: too many arguments".to_owned());
            }
            json!({ "op": "group_mention_capability", "group": args[0] })
        }
        "group-mention-send" => {
            need(4)?;
            let spans = args[3..]
                .iter()
                .map(|span| parse_mention_span(span))
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "op": "group_mention_send",
                "group": args[0],
                "review_token": args[1],
                "text": args[2],
                "spans": spans,
            })
        }
        "group-add" => {
            need(2)?;
            json!({ "op": "group_add", "group": args[0], "peer": args[1] })
        }
        "group-remove" => {
            need(2)?;
            json!({ "op": "group_remove", "group": args[0], "peer": args[1] })
        }
        "group-leave" => {
            need(1)?;
            json!({ "op": "group_leave", "group": args[0] })
        }
        "groups" => json!({ "op": "groups" }),
        "group-messages" => {
            need(1)?;
            json!({ "op": "group_messages", "group": args[0] })
        }
        "contacts" => json!({ "op": "contacts" }),
        "carriers" => json!({ "op": "carrier_capabilities" }),
        "messages" => {
            need(1)?;
            json!({ "op": "messages", "peer": args[0] })
        }
        "safety" => {
            need(1)?;
            json!({ "op": "safety_number", "peer": args[0] })
        }
        "verify" => {
            need(1)?;
            json!({ "op": "verify", "peer": args[0] })
        }
        "set-hints" => {
            need(1)?;
            json!({
                "op": "set_hints",
                "peer": args[0],
                "hints": parse_hints(&args[1..])?,
            })
        }
        "publish" => json!({ "op": "publish" }),
        "backup" => {
            need(1)?;
            json!({ "op": "backup", "path": args[0] })
        }
        "watch" => json!({ "op": "subscribe" }),
        other => return Err(format!("unknown command: {other}\n\n{USAGE}")),
    };
    Ok(request)
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("-h") || args.is_empty() {
        print!("{USAGE}");
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--help") {
        print!("{USAGE}");
        return Ok(());
    }

    let socket = if args.first().map(String::as_str) == Some("--socket") {
        args.remove(0);
        if args.is_empty() {
            return Err("--socket needs a value".to_owned());
        }
        args.remove(0)
    } else {
        std::env::var("KULTD_SOCKET")
            .map_err(|_| "no socket: pass --socket or set KULTD_SOCKET".to_owned())?
    };
    if args.is_empty() {
        return Err(format!("missing command\n\n{USAGE}"));
    }
    let command = args.remove(0);

    let mut request = build_request(&command, &args)?;

    let stream = UnixStream::connect(&socket)
        .map_err(|e| format!("cannot connect to {socket}: {e} (is kultd running?)"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("socket: {e}"))?;
    let mut reader = BufReader::new(stream);

    if matches!(command.as_str(), "label-delete" | "folder-delete")
        && request["confirm"] == json!(false)
    {
        let (kind, id_field, preview_op) = if command == "folder-delete" {
            ("folder", "folder", "folder_delete_preview")
        } else {
            ("label", "label", "label_delete_preview")
        };
        let id = request[id_field].clone();
        let preview = rpc_call(
            &mut writer,
            &mut reader,
            json!({ "op": preview_op, (id_field): id }),
            1,
        )?;
        let assignments = preview["assignments"].as_u64().unwrap_or(0);
        eprint!(
            "Delete {kind} {} and {assignments} assignment(s)? [y/N] ",
            request[id_field].as_str().unwrap_or("?")
        );
        std::io::stderr()
            .flush()
            .map_err(|error| format!("stderr: {error}"))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| format!("stdin: {error}"))?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            println!(
                "{}",
                safe_json(&json!({ "deleted": false, "assignments": assignments }))?
            );
            return Ok(());
        }
        request["confirm"] = json!(true);
        let ok = rpc_call(&mut writer, &mut reader, request, 2)?;
        println!("{}", safe_json(&ok)?);
        return Ok(());
    }

    request["id"] = json!(1);
    writer
        .write_all(format!("{request}\n").as_bytes())
        .map_err(|e| format!("socket write: {e}"))?;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("socket read: {e}"))?;
        let value: Value = serde_json::from_str(&line).map_err(|e| format!("bad response: {e}"))?;
        if let Some(event) = value.get("event") {
            // watch mode: one event per line, forever.
            println!("{}", safe_json(event)?);
            continue;
        }
        if let Some(message) = value.get("err") {
            return Err(message.as_str().unwrap_or("unknown error").to_owned());
        }
        if let Some(ok) = value.get("ok") {
            if command == "watch" {
                continue; // subscription confirmed; keep streaming
            }
            println!("{}", safe_json(ok)?);
            return Ok(());
        }
    }
    if command == "watch" {
        Ok(()) // daemon went away; the stream simply ends
    } else {
        Err("connection closed before a response arrived".to_owned())
    }
}

fn rpc_call(
    writer: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    mut request: Value,
    id: u64,
) -> Result<Value, String> {
    request["id"] = json!(id);
    writer
        .write_all(format!("{request}\n").as_bytes())
        .map_err(|error| format!("socket write: {error}"))?;
    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .map_err(|error| format!("socket read: {error}"))?
        == 0
    {
        return Err("connection closed before a response arrived".to_owned());
    }
    let value: Value =
        serde_json::from_str(&line).map_err(|error| format!("bad response: {error}"))?;
    if let Some(message) = value.get("err") {
        return Err(message.as_str().unwrap_or("unknown error").to_owned());
    }
    Ok(value["ok"].clone())
}

fn safe_json(value: &Value) -> Result<String, String> {
    let serialized = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    let mut safe = String::with_capacity(serialized.len());
    for value in serialized.chars() {
        match value {
            '\u{061c}' => safe.push_str("\\u061c"),
            '\u{200e}' => safe.push_str("\\u200e"),
            '\u{200f}' => safe.push_str("\\u200f"),
            '\u{202a}' => safe.push_str("\\u202a"),
            '\u{202b}' => safe.push_str("\\u202b"),
            '\u{202c}' => safe.push_str("\\u202c"),
            '\u{202d}' => safe.push_str("\\u202d"),
            '\u{202e}' => safe.push_str("\\u202e"),
            '\u{2066}' => safe.push_str("\\u2066"),
            '\u{2067}' => safe.push_str("\\u2067"),
            '\u{2068}' => safe.push_str("\\u2068"),
            '\u{2069}' => safe.push_str("\\u2069"),
            other => safe.push(other),
        }
    }
    Ok(safe)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kult: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_build_the_rpc_contract() {
        let request = build_request(
            "group-create",
            &["trail crew".to_owned(), "01".repeat(32), "02".repeat(32)],
        )
        .unwrap();
        assert_eq!(request["op"], json!("group_create"));
        assert_eq!(request["members"].as_array().unwrap().len(), 2);

        let request = build_request(
            "group-send",
            &["03".repeat(32), "meet".to_owned(), "there".to_owned()],
        )
        .unwrap();
        assert_eq!(request["body"], json!("meet there"));
        let request = build_request(
            "group-mention-send",
            &[
                "03".repeat(32),
                "04".repeat(16),
                "hi @Alex".to_owned(),
                format!("3:8:{}", "05".repeat(32)),
            ],
        )
        .unwrap();
        assert_eq!(request["op"], json!("group_mention_send"));
        assert_eq!(request["text"], json!("hi @Alex"));
        assert_eq!(request["spans"][0]["start"], json!(3));
        assert_eq!(request["spans"][0]["target"], json!("05".repeat(32)));
        assert!(build_request(
            "group-mention-send",
            &[
                "03".repeat(32),
                "04".repeat(16),
                "hi @Alex".to_owned(),
                "3:8:Alex".to_owned(),
            ],
        )
        .is_err());
        assert_eq!(
            build_request("groups", &[]).unwrap(),
            json!({ "op": "groups" })
        );
        assert!(build_request("group-add", &["03".repeat(32)]).is_err());
        assert_eq!(
            build_request("carriers", &[]).unwrap(),
            json!({ "op": "carrier_capabilities" })
        );
        assert_eq!(
            build_request("note", &["remember".to_owned(), "this".to_owned()]).unwrap(),
            json!({ "op": "note_to_self_send", "body": "remember this" })
        );
        assert_eq!(
            build_request("note-messages", &[]).unwrap(),
            json!({ "op": "note_to_self_messages" })
        );
        assert_eq!(
            build_request(
                "schedule",
                &["04".repeat(32), "1800000100".to_owned(), "later".to_owned()]
            )
            .unwrap(),
            json!({
                "op": "schedule",
                "peer": "04".repeat(32),
                "not_before": 1_800_000_100u64,
                "body": "later",
            })
        );
        assert_eq!(
            build_request("scheduled", &[]).unwrap(),
            json!({ "op": "scheduled_messages" })
        );
        assert!(build_request(
            "schedule-edit",
            &["01".repeat(16), "not-a-time".to_owned(), "x".to_owned()]
        )
        .is_err());

        let request = build_request(
            "attachment-send",
            &[
                "05".repeat(32),
                "/tmp/photo.jpg".to_owned(),
                "image/jpeg".to_owned(),
                "photo.jpg".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(request["op"], json!("attachment_send"));
        assert_eq!(request["filename"], json!("photo.jpg"));
        let preview_request = build_request(
            "attachment-send-preview",
            &[
                "05".repeat(32),
                "/tmp/photo.jpg".to_owned(),
                "image/jpeg".to_owned(),
                "/tmp/preview.jpg".to_owned(),
                "image/jpeg".to_owned(),
                "photo.jpg".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(preview_request["preview_path"], json!("/tmp/preview.jpg"));
        assert_eq!(
            build_request("attachment-accept", &["06".repeat(16)]).unwrap(),
            json!({ "op": "attachment_accept", "transfer": "06".repeat(16) })
        );
        assert_eq!(
            build_request(
                "attachment-preview-export",
                &["06".repeat(16), "/tmp/preview.jpg".to_owned()]
            )
            .unwrap()["preview"],
            json!(true)
        );
        assert_eq!(
            build_request(
                "attachment-export",
                &["06".repeat(16), "/tmp/export.jpg".to_owned()]
            )
            .unwrap(),
            json!({
                "op": "attachment_export",
                "transfer": "06".repeat(16),
                "path": "/tmp/export.jpg",
            })
        );

        let folder = "fa".repeat(16);
        let second_folder = "fb".repeat(16);
        let peer = "cd".repeat(32);
        assert_eq!(
            build_request("folder-create", &["e\u{301}".to_owned(), "🧭".to_owned()]).unwrap(),
            json!({ "op": "folder_create", "name": "e\u{301} 🧭" })
        );
        assert_eq!(
            build_request("folders", &[]).unwrap(),
            json!({ "op": "folders" })
        );
        assert_eq!(
            build_request("folder-get", std::slice::from_ref(&folder)).unwrap(),
            json!({ "op": "folder_get", "folder": folder })
        );
        assert_eq!(
            build_request(
                "folder-rename",
                &[folder.clone(), "exact".to_owned(), "name".to_owned()]
            )
            .unwrap(),
            json!({ "op": "folder_rename", "folder": folder, "name": "exact name" })
        );
        assert_eq!(
            build_request("folder-reorder", &[second_folder.clone(), folder.clone()]).unwrap(),
            json!({ "op": "folder_reorder", "folders": [second_folder, folder] })
        );
        assert_eq!(
            build_request("folder-move", &[folder.clone(), format!("peer:{peer}")]).unwrap(),
            json!({
                "op": "folder_move",
                "folder": folder,
                "target": { "type": "peer", "id": peer },
            })
        );
        assert_eq!(
            build_request("folder-unfile", &["note-to-self".to_owned()]).unwrap(),
            json!({ "op": "folder_unfile", "target": { "type": "note_to_self" } })
        );
        assert_eq!(
            build_request(
                "folder-conversations",
                &[folder.clone(), "all".to_owned(), "ab".repeat(16)]
            )
            .unwrap(),
            json!({
                "op": "folder_conversations",
                "selection": { "type": "folder", "id": folder },
                "mode": "all",
                "labels": ["ab".repeat(16)],
            })
        );
        assert_eq!(
            build_request("folder-delete", std::slice::from_ref(&folder)).unwrap()["confirm"],
            json!(false)
        );
        assert!(build_request("folder-create", &[" \u{200e}".to_owned()]).is_err());
        assert!(build_request("folder-move", &[folder.clone(), "bob".to_owned()]).is_err());
        assert!(build_request("folder-get", &["not-a-folder".to_owned()]).is_err());
        assert!(build_request("folders", &["trailing".to_owned()]).is_err());
        assert!(build_request(
            "folder-reorder",
            &std::iter::repeat_n(folder.clone(), 129).collect::<Vec<_>>()
        )
        .is_err());

        let created = build_request(
            "label-create",
            &[
                "teal".to_owned(),
                "e\u{301}".to_owned(),
                "\u{2067}טיול\u{2069}".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(created["op"], json!("label_create"));
        assert_eq!(created["name"], json!("e\u{301} \u{2067}טיול\u{2069}"));
        assert_eq!(created["color"], json!("teal"));
        let id = "ab".repeat(16);
        let peer = "cd".repeat(32);
        let group = "de".repeat(32);
        assert_eq!(
            build_request("labels", &[]).unwrap(),
            json!({ "op": "labels" })
        );
        assert_eq!(
            build_request("label-get", std::slice::from_ref(&id)).unwrap(),
            json!({ "op": "label_get", "label": id })
        );
        assert_eq!(
            build_request(
                "label-update",
                &[id.clone(), "purple".to_owned(), "exact name".to_owned()]
            )
            .unwrap(),
            json!({ "op": "label_update", "label": id, "name": "exact name", "color": "purple" })
        );
        assert_eq!(
            build_request("label-assign", &[id.clone(), format!("peer:{peer}")]).unwrap(),
            json!({
                "op": "label_assign",
                "label": id,
                "target": { "type": "peer", "id": peer },
            })
        );
        assert_eq!(
            build_request("label-unassign", &[id.clone(), format!("group:{group}")]).unwrap(),
            json!({
                "op": "label_unassign",
                "label": id,
                "target": { "type": "group", "id": group },
            })
        );
        assert_eq!(
            build_request("label-membership", std::slice::from_ref(&id)).unwrap(),
            json!({ "op": "label_membership", "label": id })
        );
        assert_eq!(
            build_request("labels-for", &["note-to-self".to_owned()]).unwrap(),
            json!({ "op": "labels_for_conversation", "target": { "type": "note_to_self" } })
        );
        assert_eq!(
            build_request("label-stale", &[]).unwrap(),
            json!({ "op": "label_stale" })
        );
        assert_eq!(
            build_request(
                "label-stale-cleanup",
                &[id.clone(), format!("group:{group}")]
            )
            .unwrap(),
            json!({
                "op": "label_stale_cleanup",
                "label": id,
                "target": { "type": "group", "id": group },
            })
        );
        assert_eq!(
            build_request("label-filter", &["all".to_owned(), id.clone(), id.clone()]).unwrap(),
            json!({ "op": "label_filter", "mode": "all", "labels": [id, id] })
        );
        assert_eq!(
            build_request("label-delete", std::slice::from_ref(&id)).unwrap()["confirm"],
            json!(false)
        );
        assert_eq!(
            build_request("label-delete", &[id.clone(), "--yes".to_owned()]).unwrap()["confirm"],
            json!(true)
        );
        assert!(
            build_request("label-create", &["css:red".to_owned(), "unsafe".to_owned()]).is_err()
        );
        assert!(build_request("label-assign", &[id.clone(), "bob".to_owned()]).is_err());
        assert!(build_request("label-get", &["not-a-label-name".to_owned()]).is_err());
        assert!(build_request("labels", &["trailing".to_owned()]).is_err());
        assert!(build_request("label-stale", &["trailing".to_owned()]).is_err());
        assert!(build_request("label-delete", &[id.clone(), "--force".to_owned()]).is_err());
        assert!(build_request(
            "label-filter",
            &std::iter::once("any".to_owned())
                .chain(std::iter::repeat_n(id.clone(), 129))
                .collect::<Vec<_>>()
        )
        .is_err());

        let peer_target = format!("peer:{}", "12".repeat(32));
        let group_target = format!("group:{}", "34".repeat(32));
        assert_eq!(
            build_request("pin", std::slice::from_ref(&peer_target)).unwrap(),
            json!({ "op": "pin", "target": { "type": "peer", "id": "12".repeat(32) } })
        );
        assert_eq!(
            build_request("unpin", &["note-to-self".to_owned()]).unwrap(),
            json!({ "op": "unpin", "target": { "type": "note_to_self" } })
        );
        assert_eq!(
            build_request("pin-state", std::slice::from_ref(&group_target)).unwrap(),
            json!({ "op": "pin_state", "target": { "type": "group", "id": "34".repeat(32) } })
        );
        assert_eq!(build_request("pins", &[]).unwrap(), json!({ "op": "pins" }));
        assert_eq!(
            build_request("pin-reorder", &[group_target.clone(), peer_target.clone()]).unwrap(),
            json!({
                "op": "pin_reorder",
                "targets": [
                    { "type": "group", "id": "34".repeat(32) },
                    { "type": "peer", "id": "12".repeat(32) },
                ],
            })
        );
        assert_eq!(
            build_request("pin-stale", &[]).unwrap(),
            json!({ "op": "pin_stale" })
        );
        assert_eq!(
            build_request("pin-stale-cleanup", std::slice::from_ref(&group_target)).unwrap(),
            json!({ "op": "pin_stale_cleanup", "target": { "type": "group", "id": "34".repeat(32) } })
        );
        assert_eq!(
            build_request(
                "pin-conversations",
                &["unfiled".to_owned(), "all".to_owned(), id.clone()]
            )
            .unwrap(),
            json!({
                "op": "pin_conversations",
                "selection": { "type": "unfiled" },
                "mode": "all",
                "labels": [id],
            })
        );
        assert!(build_request("pin", &[]).is_err());
        assert!(build_request("pins", &["trailing".to_owned()]).is_err());
        assert!(build_request("pin-reorder", &["bob".to_owned()]).is_err());
        assert!(build_request(
            "pin-conversations",
            &["all".to_owned(), "neither".to_owned()]
        )
        .is_err());

        let exact = json!({ "name": "a\u{202e}b\u{2067}c\u{2069}" });
        let rendered = safe_json(&exact).unwrap();
        assert!(rendered.contains("\\u202e"));
        assert!(rendered.contains("\\u2067"));
        assert_eq!(serde_json::from_str::<Value>(&rendered).unwrap(), exact);
    }
}
