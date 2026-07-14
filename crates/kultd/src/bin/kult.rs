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
    note TEXT...                    append to the local note-to-self conversation
    note-messages                   local note-to-self history
    group-create NAME [MEMBER_HEX]... create a sender-key group
    group-send GROUP_HEX TEXT...     queue a group message
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
    }
}
