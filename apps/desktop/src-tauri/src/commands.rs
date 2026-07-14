//! The Tauri command surface: one-line wrappers around [`Session`]. All
//! node calls are blocking by design (kult-ffi's contract), so every
//! command is `async` and hops through `spawn_blocking` — the UI thread
//! never waits on Argon2id or the network.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kult_ffi::KdfChoice;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::session::{
    NetworkSettings, Session, UiAttachment, UiAudioMedia, UiBundle, UiContact, UiGroup,
    UiGroupMessage, UiHint, UiMessage, UiNoteMessage, UiSafetyNumber, UiScheduledMessage, UiStatus,
};

/// The one piece of managed state: the running session, if unlocked.
#[derive(Default)]
pub struct AppState(pub Mutex<Option<Arc<Session>>>);

impl AppState {
    /// The session, or an honest "locked" error.
    fn session(&self) -> Result<Arc<Session>, String> {
        self.0
            .lock()
            .expect("state lock")
            .clone()
            .ok_or_else(|| "locked — unlock first".to_owned())
    }

    /// Take the session out (for lock/shutdown).
    pub fn take(&self) -> Option<Arc<Session>> {
        self.0.lock().expect("state lock").take()
    }
}

/// What the unlock screen needs before any passphrase is typed.
#[derive(Serialize)]
pub struct Probe {
    /// The default data directory for this platform.
    pub data_dir: String,
    /// Whether a store already exists there (open vs. create vs. restore).
    pub exists: bool,
    /// Persisted network settings (defaults on first run).
    pub settings: NetworkSettings,
}

/// Run a blocking session call off the async runtime's worker threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

/// Default data dir, store presence, and saved settings.
#[tauri::command]
pub fn probe(app: AppHandle, data_dir: Option<String>) -> Result<Probe, String> {
    let dir = match data_dir {
        Some(d) if !d.trim().is_empty() => PathBuf::from(d.trim()),
        _ => app
            .path()
            .app_data_dir()
            .map_err(|e| format!("no data dir: {e}"))?,
    };
    Ok(Probe {
        exists: dir.join("node.db").exists(),
        settings: NetworkSettings::load(&dir)?,
        data_dir: dir.display().to_string(),
    })
}

/// Open (or create) the store and start the node. Returns the kult
/// address. Settings are persisted so the next unlock reuses them.
#[tauri::command]
pub async fn unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    data_dir: String,
    passphrase: String,
    settings: NetworkSettings,
) -> Result<String, String> {
    start_session(
        &app,
        &state,
        data_dir,
        settings,
        move |dir, settings, sink| {
            Session::open(dir, passphrase, settings, KdfChoice::Desktop, sink)
        },
    )
    .await
}

/// First run only: restore from an encrypted backup, then start.
#[tauri::command]
pub async fn restore(
    app: AppHandle,
    state: State<'_, AppState>,
    data_dir: String,
    passphrase: String,
    backup_path: String,
    mnemonic: String,
    settings: NetworkSettings,
) -> Result<String, String> {
    start_session(
        &app,
        &state,
        data_dir,
        settings,
        move |dir, settings, sink| {
            Session::restore(
                dir,
                passphrase,
                backup_path,
                mnemonic,
                settings,
                KdfChoice::Desktop,
                sink,
            )
        },
    )
    .await
}

/// Shared tail of `unlock`/`restore`: refuse double-unlock, persist
/// settings, boot with events wired to the webview, publish the handle.
async fn start_session(
    app: &AppHandle,
    state: &State<'_, AppState>,
    data_dir: String,
    settings: NetworkSettings,
    boot: impl FnOnce(
            &std::path::Path,
            &NetworkSettings,
            crate::session::EventSink,
        ) -> Result<Session, String>
        + Send
        + 'static,
) -> Result<String, String> {
    if state.0.lock().expect("state lock").is_some() {
        return Err("already unlocked".to_owned());
    }
    let emitter = app.clone();
    let session = blocking(move || {
        let dir = PathBuf::from(&data_dir);
        settings.save(&dir)?;
        let sink: crate::session::EventSink = Box::new(move |event| {
            // A closed webview drops events on the floor — the node's own
            // store is the source of truth, the event stream is a nudge.
            let _ = emitter.emit("node-event", &event);
        });
        boot(&dir, &settings, sink)
    })
    .await?;
    let address = session.address();
    *state.0.lock().expect("state lock") = Some(Arc::new(session));
    Ok(address)
}

/// Stop the node and forget the session (idempotent).
#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(session) = state.take() {
        blocking(move || {
            session.stop();
            Ok(())
        })
        .await?;
    }
    Ok(())
}

macro_rules! forward {
    ($(#[$doc:meta])* $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty, |$s:ident| $body:expr) => {
        $(#[$doc])*
        #[tauri::command]
        pub async fn $name(state: State<'_, AppState>, $($arg: $ty),*) -> Result<$ret, String> {
            let $s = state.session()?;
            blocking(move || $body).await
        }
    };
}

forward!(
    /// Status snapshot for the transport indicators.
    status() -> UiStatus, |s| s.status()
);
forward!(
    /// Validate and send an explicitly confirmed pairwise audio recording.
    send_recorded_audio(peer: String, encoded: String) -> String,
    |s| s.send_recorded_audio(peer, encoded)
);
forward!(
    /// Validate and send an explicitly confirmed group audio recording.
    send_group_recorded_audio(group: String, encoded: String) -> String,
    |s| s.send_group_recorded_audio(group, encoded)
);
forward!(
    /// Explain the current authoritative carrier gate for an audio confirmation.
    audio_carrier_explanation(conversation: String, destination: String) -> String,
    |s| s.audio_carrier_explanation(conversation, destination)
);
forward!(
    /// Schedule pairwise text for an absolute UTC Unix instant.
    schedule(peer: String, body: String, not_before: u64) -> String,
    |s| s.schedule(peer, body, not_before)
);
forward!(
    /// Schedule group text for an absolute UTC Unix instant.
    schedule_group(group: String, body: String, not_before: u64) -> String,
    |s| s.schedule_group(group, body, not_before)
);
forward!(
    /// Full durable scheduled outbox.
    scheduled_messages() -> Vec<UiScheduledMessage>, |s| s.scheduled_messages()
);
forward!(
    /// Edit scheduled text and/or its UTC instant.
    edit_scheduled(message: String, body: String, not_before: u64) -> (),
    |s| s.edit_scheduled(message, body, not_before)
);
forward!(
    /// Cancel a scheduled message before activation.
    cancel_scheduled(message: String) -> (), |s| s.cancel_scheduled(message)
);
forward!(
    /// A QR of this node's kult address.
    address_qr() -> String, |s| s.address_qr()
);
forward!(
    /// Fresh prekey bundle: pasteable hex + QR.
    my_bundle() -> UiBundle, |s| s.my_bundle()
);
forward!(
    /// Add a contact from bundle hex with delivery hints.
    add_contact(name: String, bundle_hex: String, hints: Vec<UiHint>) -> String,
    |s| s.add_contact(name, &bundle_hex, &hints)
);
forward!(
    /// Add a contact from their kult address (DHT lookup).
    add_contact_by_address(name: String, address: String) -> String,
    |s| s.add_contact_by_address(name, address)
);
forward!(
    /// All stored contacts.
    contacts() -> Vec<UiContact>, |s| s.contacts()
);
forward!(
    /// Message history with a peer.
    messages(peer: String) -> Vec<UiMessage>, |s| s.messages(peer)
);
forward!(
    /// Queue a message; progress arrives as `node-event`s.
    send(peer: String, body: String) -> String, |s| s.send(peer, body)
);
forward!(
    /// Import a caller-selected file as a pairwise attachment.
    send_attachment(
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>
    ) -> String,
    |s| s.send_attachment(peer, path, media_type, filename)
);
forward!(
    /// Import a caller-selected file as an encrypt-once group attachment.
    send_group_attachment(
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>
    ) -> String,
    |s| s.send_group_attachment(group, path, media_type, filename)
);
forward!(
    /// Every attachment transfer as render-safe state.
    attachments() -> Vec<UiAttachment>, |s| s.attachments()
);
forward!(
    /// Accept an inbound attachment offer.
    accept_attachment(transfer: String) -> (), |s| s.accept_attachment(transfer)
);
forward!(
    /// Durably reject an inbound attachment offer.
    reject_attachment(transfer: String) -> (), |s| s.reject_attachment(transfer)
);
forward!(
    /// Cancel local transfer activity.
    cancel_attachment(transfer: String) -> (), |s| s.cancel_attachment(transfer)
);
forward!(
    /// Pause transfer activity while retaining verified progress.
    pause_attachment(transfer: String) -> (), |s| s.pause_attachment(transfer)
);
forward!(
    /// Resume a paused transfer.
    resume_attachment(transfer: String) -> (), |s| s.resume_attachment(transfer)
);
forward!(
    /// Export a completed primary object to a protected new path.
    export_attachment(transfer: String, path: String) -> (), |s| s.export_attachment(transfer, path)
);
forward!(
    /// Return a completed sealed preview as a bounded data URL.
    attachment_preview(transfer: String) -> String, |s| s.attachment_preview(transfer)
);
forward!(
    /// Return completed canonical audio through bounded protected playback materialization.
    attachment_audio(transfer: String) -> UiAudioMedia, |s| s.attachment_audio(transfer)
);
forward!(
    /// Stable reserved identity for the local note-to-self conversation.
    note_to_self_id() -> String, |s| Ok(s.note_to_self_id())
);
forward!(
    /// All sealed local-only note-to-self entries.
    note_to_self_messages() -> Vec<UiNoteMessage>, |s| s.note_to_self_messages()
);
forward!(
    /// Append one sealed local-only note.
    send_note_to_self(body: String) -> String, |s| s.send_note_to_self(body)
);
forward!(
    /// Create a sender-key group from stored contacts.
    create_group(name: String, members: Vec<String>) -> String,
    |s| s.create_group(name, members)
);
forward!(
    /// All locally stored groups.
    groups() -> Vec<UiGroup>, |s| s.groups()
);
forward!(
    /// Group history with per-member delivery states.
    group_messages(group: String) -> Vec<UiGroupMessage>, |s| s.group_messages(group)
);
forward!(
    /// Queue a message to a group.
    send_group(group: String, body: String) -> String, |s| s.send_group(group, body)
);
forward!(
    /// Add a stored contact to a group (creator only).
    add_group_member(group: String, peer: String) -> (), |s| s.add_group_member(group, peer)
);
forward!(
    /// Remove a member and rotate group keys (creator only).
    remove_group_member(group: String, peer: String) -> (),
    |s| s.remove_group_member(group, peer)
);
forward!(
    /// Leave a group and drop its live local state.
    leave_group(group: String) -> (), |s| s.leave_group(group)
);
forward!(
    /// Safety number + QR for out-of-band verification.
    safety_number(peer: String) -> UiSafetyNumber, |s| s.safety_number(peer)
);
forward!(
    /// Record that safety numbers were verified out-of-band.
    mark_verified(peer: String) -> (), |s| s.mark_verified(peer)
);
forward!(
    /// Replace a contact's delivery hints.
    set_hints(peer: String, hints: Vec<UiHint>) -> (), |s| s.set_hints(peer, &hints)
);
forward!(
    /// Publish the prekey bundle on the DHT now.
    publish() -> (), |s| s.publish()
);
forward!(
    /// Encrypted backup to `path`; returns the one-time 24-word mnemonic.
    export_backup(path: String) -> String, |s| s.export_backup(path)
);
