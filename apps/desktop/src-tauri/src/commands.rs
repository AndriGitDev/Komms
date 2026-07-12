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
    NetworkSettings, Session, UiBundle, UiContact, UiHint, UiMessage, UiSafetyNumber, UiStatus,
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
