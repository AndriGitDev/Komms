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
    NetworkSettings, Session, UiAttachment, UiAudioMedia, UiBundle, UiContact,
    UiContactNameAssessment, UiCustomIcon, UiCustomIconCrop, UiCustomIconTarget, UiCustomIconUsage,
    UiFolder, UiFolderConversation, UiFolderConversationResult, UiFolderSelection, UiFolderTarget,
    UiFormattedText, UiGroup, UiGroupAuthority, UiGroupMessage, UiGroupPoll, UiHint,
    UiImageEditRecipe, UiImageReview, UiLabel, UiLabelConversation, UiLabelFilterResult,
    UiLabelTarget, UiMentionCapability, UiMentionSpan, UiMessage, UiNoteMessage, UiPin,
    UiPinConversationResult, UiPinTarget, UiSafetyNumber, UiScheduledMessage, UiStaleFolder,
    UiStaleLabel, UiStatus, UiTextFormatHighlight, UiThemeInfo, UiThemePreference,
};

/// Render-safe shared B14 policy shown before unlock.
#[derive(Serialize)]
pub struct UiScreenSecurityPolicy {
    /// Protection is mandatory and starts before the store opens.
    pub always_on: bool,
    /// Short native-mechanism description.
    pub mechanism: String,
    /// Exact environment limitations.
    pub limitations: Vec<String>,
    /// Stable capability token for screenshots and recording.
    pub capture_prevention: String,
    /// Stable capability token for recent/task previews.
    pub background_obscuring: String,
    /// Stable capability token for the rapid lock shortcut.
    pub rapid_lock: String,
}

/// Shared desktop screen-security promise; available while locked.
#[tauri::command]
pub fn screen_security_policy() -> UiScreenSecurityPolicy {
    let policy = kult_ffi::screen_security_policy(kult_ffi::ScreenSecurityPlatform::Desktop);
    let level = |value| match value {
        kult_ffi::ScreenSecurityLevel::PlatformEnforced => "platform_enforced",
        kult_ffi::ScreenSecurityLevel::BestEffort => "best_effort",
        kult_ffi::ScreenSecurityLevel::Unavailable => "unavailable",
    };
    UiScreenSecurityPolicy {
        always_on: policy.always_on,
        mechanism: policy.mechanism,
        limitations: policy.limitations,
        capture_prevention: level(policy.capture_prevention).to_owned(),
        background_obscuring: level(policy.background_obscuring).to_owned(),
        rapid_lock: level(policy.rapid_lock).to_owned(),
    }
}

/// Render-safe shared B15 input-privacy policy shown before unlock.
#[derive(Serialize)]
pub struct UiIncognitoKeyboardPolicy {
    /// Input privacy is mandatory for every textual field.
    pub always_on: bool,
    /// Unlock and restore inputs are covered before the store opens.
    pub applies_before_unlock: bool,
    /// Short native-mechanism description.
    pub mechanism: String,
    /// Exact environment limitations.
    pub limitations: Vec<String>,
    /// Stable capability token for personalized learning.
    pub personalized_learning: String,
    /// Stable capability token for correction and prediction.
    pub suggestions: String,
    /// Stable capability token for spelling services.
    pub spellcheck: String,
    /// Stable capability token for secret-field masking.
    pub secret_text_masking: String,
    /// Semantic field classes every shell must protect.
    pub protected_fields: Vec<String>,
}

/// Shared desktop B15 promise; available while locked.
#[tauri::command]
pub fn incognito_keyboard_policy() -> UiIncognitoKeyboardPolicy {
    let policy = kult_ffi::incognito_keyboard_policy(kult_ffi::IncognitoKeyboardPlatform::Desktop);
    let level = |value| match value {
        kult_ffi::IncognitoKeyboardLevel::PlatformEnforced => "platform_enforced",
        kult_ffi::IncognitoKeyboardLevel::PlatformRequested => "platform_requested",
        kult_ffi::IncognitoKeyboardLevel::BestEffort => "best_effort",
        kult_ffi::IncognitoKeyboardLevel::Unavailable => "unavailable",
    };
    UiIncognitoKeyboardPolicy {
        always_on: policy.always_on,
        applies_before_unlock: policy.applies_before_unlock,
        mechanism: policy.mechanism,
        limitations: policy.limitations,
        personalized_learning: level(policy.personalized_learning).to_owned(),
        suggestions: level(policy.suggestions).to_owned(),
        spellcheck: level(policy.spellcheck).to_owned(),
        secret_text_masking: level(policy.secret_text_masking).to_owned(),
        protected_fields: policy.protected_fields,
    }
}

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
        #[allow(clippy::too_many_arguments)] // flat Tauri IPC boundary
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
    /// Render exact source into the bounded inert local text model.
    format_text(source: String, highlights: Vec<UiTextFormatHighlight>) -> UiFormattedText,
    |s| s.format_text(source, highlights)
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
    /// Explain the current authoritative carrier gate for a file/image confirmation.
    attachment_carrier_explanation(conversation: String, destination: String) -> String,
    |s| s.attachment_carrier_explanation(conversation, destination)
);
forward!(
    /// Privately stage and normalize one caller-selected JPEG/PNG.
    begin_image_edit(path: String) -> UiImageReview,
    |s| s.begin_image_edit(path)
);
forward!(
    /// Render a deterministic replacement final for one protected image draft.
    update_image_edit(token: String, recipe: UiImageEditRecipe) -> UiImageReview,
    |s| s.update_image_edit(token, recipe)
);
forward!(
    /// Delete every protected path associated with an image draft.
    discard_image_edit(token: String) -> (),
    |s| s.discard_image_edit(token)
);
forward!(
    /// Import only the exact reviewed edited image after carrier reconfirmation.
    send_image_edit(
        token: String,
        conversation: String,
        destination: String,
        filename: Option<String>,
        expected_carrier: String,
        view_once: bool,
        lifetime_secs: u64
    ) -> String,
    |s| s.send_image_edit(token, conversation, destination, filename, expected_carrier, view_once, lifetime_secs)
);
forward!(
    /// Stage and import one explicitly confirmed non-image file.
    send_confirmed_attachment(
        conversation: String,
        destination: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        expected_carrier: String
    ) -> String,
    |s| s.send_confirmed_attachment(
        conversation,
        destination,
        path,
        media_type,
        filename,
        expected_carrier
    )
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
    /// Assess a proposed private local petname without mutation.
    assess_contact_name(peer: String, name: String) -> UiContactNameAssessment,
    |s| s.assess_contact_name(peer, name)
);
forward!(
    /// Rename a contact locally by peer id after explicit warning review.
    rename_contact(peer: String, name: String, accept_warnings: bool) -> UiContactNameAssessment,
    |s| s.rename_contact(peer, name, accept_warnings)
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
    /// Queue pairwise text with exact local expiry.
    send_disappearing(peer: String, body: String, lifetime_secs: u64) -> String,
    |s| s.send_disappearing(peer, body, lifetime_secs)
);
forward!(
    /// Queue an immutable edit for an exact pairwise Text event.
    edit_message(peer: String, target_author: String, target_content_id: String, text: String) -> String,
    |s| s.edit_message(peer, target_author, target_content_id, text)
);
forward!(
    /// Every attachment transfer as render-safe state.
    attachments() -> Vec<UiAttachment>, |s| s.attachments()
);
forward!(
    /// Import a pairwise view-once attachment.
    send_view_once_attachment(peer: String, path: String, media_type: String, filename: Option<String>, lifetime_secs: u64) -> String,
    |s| s.send_view_once_attachment(peer, path, media_type, filename, lifetime_secs)
);
forward!(
    /// Import a group view-once attachment.
    send_group_view_once_attachment(group: String, path: String, media_type: String, filename: Option<String>, lifetime_secs: u64) -> String,
    |s| s.send_group_view_once_attachment(group, path, media_type, filename, lifetime_secs)
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
    /// Terminal first-open of view-once media into a protected new path.
    consume_view_once_attachment(transfer: String, path: String) -> (),
    |s| s.consume_view_once_attachment(transfer, path)
);
forward!(
    /// Explicitly hand a recognized completed inbound file to the operating system.
    open_attachment(transfer: String) -> (), |s| s.open_attachment(transfer)
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
    /// Return a completed canonical edited image through protected materialization.
    attachment_image(transfer: String) -> String, |s| s.attachment_image(transfer)
);
forward!(
    /// Stable reserved identity for the local note-to-self conversation.
    note_to_self_id() -> String, |s| Ok(s.note_to_self_id())
);
forward!(
    /// Read the private local appearance choice.
    theme() -> UiThemeInfo, |s| s.theme()
);
forward!(
    /// Idempotently persist one canonical appearance choice.
    set_theme(preference: UiThemePreference) -> bool, |s| s.set_theme(preference)
);
forward!(
    /// Read one private local icon or generated-initials fallback.
    custom_icon(target: UiCustomIconTarget) -> Option<UiCustomIcon>, |s| s.custom_icon(target)
);
forward!(
    /// Crop, sanitize, and seal a selected local JPEG/PNG.
    set_custom_icon_from_path(target: UiCustomIconTarget, path: String, crop: Option<UiCustomIconCrop>) -> UiCustomIcon,
    |s| s.set_custom_icon_from_path(target, path, crop)
);
forward!(
    /// Render and seal one bundled glyph token.
    set_bundled_custom_icon(target: UiCustomIconTarget, glyph: String) -> UiCustomIcon,
    |s| s.set_bundled_custom_icon(target, glyph)
);
forward!(
    /// Remove one icon and return to generated initials.
    clear_custom_icon(target: UiCustomIconTarget) -> bool, |s| s.clear_custom_icon(target)
);
forward!(
    /// Read sealed custom-icon quota usage.
    custom_icon_usage() -> UiCustomIconUsage, |s| s.custom_icon_usage()
);
forward!(
    /// Create one private local folder.
    create_folder(name: String) -> UiFolder, |s| s.create_folder(name)
);
forward!(
    /// List private folders in deterministic manual order.
    folders() -> Vec<UiFolder>, |s| s.folders()
);
forward!(
    /// Get one private folder by exact id.
    folder(folder: String) -> UiFolder, |s| s.folder(folder)
);
forward!(
    /// Rename one folder without changing identity or membership.
    rename_folder(folder: String, name: String) -> UiFolder, |s| s.rename_folder(folder, name)
);
forward!(
    /// Atomically reorder the complete active folder id set.
    reorder_folders(folders: Vec<String>) -> Vec<UiFolder>, |s| s.reorder_folders(folders)
);
forward!(
    /// Preview assignment count before destructive folder deletion.
    folder_delete_assignment_count(folder: String) -> u64,
    |s| s.folder_delete_assignment_count(folder)
);
forward!(
    /// Atomically delete a folder and cascade assignments to Unfiled.
    delete_folder(folder: String, confirm: bool) -> u64, |s| s.delete_folder(folder, confirm)
);
forward!(
    /// Idempotently move one exact typed conversation into a folder.
    move_to_folder(folder: String, target: UiFolderTarget) -> bool,
    |s| s.move_to_folder(folder, target)
);
forward!(
    /// Idempotently move one exact typed conversation to Unfiled.
    unfile_conversation(target: UiFolderTarget) -> bool, |s| s.unfile_conversation(target)
);
forward!(
    /// Active typed conversations for one folder.
    folder_membership(folder: String) -> Vec<UiFolderConversation>, |s| s.folder_membership(folder)
);
forward!(
    /// Active folder for one exact typed conversation.
    conversation_folder(target: UiFolderTarget) -> Option<UiFolder>,
    |s| s.conversation_folder(target)
);
forward!(
    /// Folder-first navigation composed with label filtering.
    folder_conversations(selection: UiFolderSelection, labels: Vec<String>, mode: String) -> UiFolderConversationResult,
    |s| s.folder_conversations(selection, labels, mode)
);
forward!(
    /// Render-safe stale local folder assignments.
    stale_folders() -> Vec<UiStaleFolder>, |s| s.stale_folders()
);
forward!(
    /// Remove one exact folder assignment only while it remains stale.
    cleanup_stale_folder(folder: String, target: UiFolderTarget) -> bool,
    |s| s.cleanup_stale_folder(folder, target)
);
forward!(
    /// Create one private local label.
    create_label(name: String, color: String) -> UiLabel, |s| s.create_label(name, color)
);
forward!(
    /// List private labels in stable insertion order.
    labels() -> Vec<UiLabel>, |s| s.labels()
);
forward!(
    /// Get one private label by exact id.
    label(label: String) -> UiLabel, |s| s.label(label)
);
forward!(
    /// Rename/recolor one label without changing identity.
    update_label(label: String, name: String, color: String) -> UiLabel,
    |s| s.update_label(label, name, color)
);
forward!(
    /// Preview membership count before destructive deletion.
    label_delete_assignment_count(label: String) -> u64,
    |s| s.label_delete_assignment_count(label)
);
forward!(
    /// Atomically delete a label and memberships after explicit confirmation.
    delete_label(label: String, confirm: bool) -> u64, |s| s.delete_label(label, confirm)
);
forward!(
    /// Idempotently assign one label to an exact typed target.
    assign_label(label: String, target: UiLabelTarget) -> bool, |s| s.assign_label(label, target)
);
forward!(
    /// Idempotently unassign one exact membership.
    unassign_label(label: String, target: UiLabelTarget) -> bool, |s| s.unassign_label(label, target)
);
forward!(
    /// Active typed conversations for one label.
    label_membership(label: String) -> Vec<UiLabelConversation>, |s| s.label_membership(label)
);
forward!(
    /// Active labels for one exact typed conversation.
    labels_for_conversation(target: UiLabelTarget) -> Vec<UiLabel>,
    |s| s.labels_for_conversation(target)
);
forward!(
    /// Render-safe stale local label memberships.
    stale_labels() -> Vec<UiStaleLabel>, |s| s.stale_labels()
);
forward!(
    /// Remove one exact membership only while it remains stale.
    cleanup_stale_label(label: String, target: UiLabelTarget) -> bool,
    |s| s.cleanup_stale_label(label, target)
);
forward!(
    /// Deterministically filter eligible conversations by labels.
    filter_labels(labels: Vec<String>, mode: String) -> UiLabelFilterResult,
    |s| s.filter_labels(labels, mode)
);
forward!(
    /// Idempotently pin one exact typed conversation.
    pin_conversation(target: UiPinTarget) -> bool, |s| s.pin_conversation(target)
);
forward!(
    /// Idempotently unpin one exact typed conversation.
    unpin_conversation(target: UiPinTarget) -> bool, |s| s.unpin_conversation(target)
);
forward!(
    /// Inspect one exact target's durable pin state.
    pin_state(target: UiPinTarget) -> Option<UiPin>, |s| s.pin_state(target)
);
forward!(
    /// List every active or stale durable pin.
    pins() -> Vec<UiPin>, |s| s.pins()
);
forward!(
    /// Atomically reorder the complete durable pin set.
    reorder_pins(targets: Vec<UiPinTarget>) -> Vec<UiPin>, |s| s.reorder_pins(targets)
);
forward!(
    /// List unavailable durable pins.
    stale_pins() -> Vec<UiPin>, |s| s.stale_pins()
);
forward!(
    /// Remove one exact pin only while unavailable.
    cleanup_stale_pin(target: UiPinTarget) -> bool, |s| s.cleanup_stale_pin(target)
);
forward!(
    /// Compose folder, label, and pin-aware conversation ordering.
    pin_conversations(selection: UiFolderSelection, labels: Vec<String>, mode: String) -> UiPinConversationResult,
    |s| s.pin_conversations(selection, labels, mode)
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
    /// Queue group text with exact local expiry.
    send_group_disappearing(group: String, body: String, lifetime_secs: u64) -> String,
    |s| s.send_group_disappearing(group, body, lifetime_secs)
);
forward!(
    /// Queue an immutable edit for an exact group Text event.
    edit_group_message(group: String, target_author: String, target_content_id: String, text: String) -> String,
    |s| s.edit_group_message(group, target_author, target_content_id, text)
);
forward!(
    /// Current all-member semantic Mention support and review binding.
    group_mention_capability(group: String) -> UiMentionCapability,
    |s| s.group_mention_capability(group)
);
forward!(
    /// Send exact fallback text with explicit stable peer Mention spans.
    send_group_mention(
        group: String,
        text: String,
        spans: Vec<UiMentionSpan>,
        review_token: String
    ) -> String,
    |s| s.send_group_mention(group, text, spans, review_token)
);
forward!(
    /// Create a visible-vote single-choice group poll.
    create_group_poll(group: String, question: String, options: Vec<String>) -> String,
    |s| s.create_group_poll(group, question, options)
);
forward!(
    /// List render-safe group poll cards and visible tallies.
    group_polls(group: String) -> Vec<UiGroupPoll>, |s| s.group_polls(group)
);
forward!(
    /// Cast or change a vote using stable ids.
    vote_group_poll(group: String, poll_author: String, poll_id: String, option_id: String) -> String,
    |s| s.vote_group_poll(group, poll_author, poll_id, option_id)
);
forward!(
    /// Creator-only irreversible poll closure.
    close_group_poll(group: String, poll_author: String, poll_id: String) -> String,
    |s| s.close_group_poll(group, poll_author, poll_id)
);
forward!(
    /// Signed owner/admin poll moderation closure.
    moderate_group_poll_close(group: String, poll_author: String, poll_id: String) -> String,
    |s| s.moderate_group_poll_close(group, poll_author, poll_id)
);
forward!(
    /// Current exact group roles and ownership.
    group_authority(group: String) -> UiGroupAuthority, |s| s.group_authority(group)
);
forward!(
    /// Upgrade legacy creator authority.
    upgrade_group_authority(group: String) -> String, |s| s.upgrade_group_authority(group)
);
forward!(
    /// Rename directly as owner or request as admin.
    rename_group(group: String, name: String) -> String, |s| s.rename_group(group, name)
);
forward!(
    /// Owner-only admin grant/revoke.
    set_group_role(group: String, peer: String, role: String) -> String,
    |s| s.set_group_role(group, peer, role)
);
forward!(
    /// Owner-only ownership transfer.
    transfer_group_owner(group: String, peer: String) -> String,
    |s| s.transfer_group_owner(group, peer)
);
forward!(
    /// Add a stored contact as owner or request as admin.
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
