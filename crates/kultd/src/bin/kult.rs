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
    request["id"] = json!(1);

    let stream = UnixStream::connect(&socket)
        .map_err(|e| format!("cannot connect to {socket}: {e} (is kultd running?)"))?;
    let mut writer = stream.try_clone().map_err(|e| format!("socket: {e}"))?;
    writer
        .write_all(format!("{request}\n").as_bytes())
        .map_err(|e| format!("socket write: {e}"))?;

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line.map_err(|e| format!("socket read: {e}"))?;
        let value: Value = serde_json::from_str(&line).map_err(|e| format!("bad response: {e}"))?;
        if let Some(event) = value.get("event") {
            // watch mode: one event per line, forever.
            println!("{event}");
            continue;
        }
        if let Some(message) = value.get("err") {
            return Err(message.as_str().unwrap_or("unknown error").to_owned());
        }
        if let Some(ok) = value.get("ok") {
            if command == "watch" {
                continue; // subscription confirmed; keep streaming
            }
            println!(
                "{}",
                serde_json::to_string_pretty(ok).map_err(|e| e.to_string())?
            );
            return Ok(());
        }
    }
    if command == "watch" {
        Ok(()) // daemon went away; the stream simply ends
    } else {
        Err("connection closed before a response arrived".to_owned())
    }
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
    fn group_commands_build_the_rpc_contract() {
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
    }
}
