//! Komms desktop (application A1, docs/03-architecture.md): a Tauri shell
//! over `kult-ffi`'s embedded node runtime — the exact surface the mobile
//! shells consume, dogfooded on the desktop.
//!
//! Layering:
//! - [`session`] — everything the app can do, as a webview-agnostic,
//!   testable layer over [`kult_ffi::KultNode`] (view-models, settings,
//!   hex/QR plumbing). The integration tests drive this directly.
//! - [`commands`] — the Tauri IPC surface: one-line async wrappers that
//!   hop through `spawn_blocking` (node calls block by FFI contract).
//! - `ui/` (sibling directory) — a dependency-free HTML/CSS/JS frontend;
//!   no bundler, no npm. Node events reach it as `node-event` emissions.
//!
//! The shell adds no protocol logic and keeps the core's honesty rules:
//! delivery states and errors are the node's own, and the backup mnemonic
//! passes through exactly once.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod commands;
pub mod qr;
pub mod session;

use tauri::Manager;

/// Build and run the Tauri application (called from `main`).
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::unlock,
            commands::restore,
            commands::lock,
            commands::status,
            commands::address_qr,
            commands::my_bundle,
            commands::add_contact,
            commands::add_contact_by_address,
            commands::contacts,
            commands::messages,
            commands::send,
            commands::send_attachment,
            commands::send_group_attachment,
            commands::attachments,
            commands::accept_attachment,
            commands::reject_attachment,
            commands::cancel_attachment,
            commands::pause_attachment,
            commands::resume_attachment,
            commands::export_attachment,
            commands::schedule,
            commands::schedule_group,
            commands::scheduled_messages,
            commands::edit_scheduled,
            commands::cancel_scheduled,
            commands::note_to_self_id,
            commands::note_to_self_messages,
            commands::send_note_to_self,
            commands::create_group,
            commands::groups,
            commands::group_messages,
            commands::send_group,
            commands::add_group_member,
            commands::remove_group_member,
            commands::leave_group,
            commands::safety_number,
            commands::mark_verified,
            commands::set_hints,
            commands::publish,
            commands::export_backup,
        ])
        .on_window_event(|window, event| {
            // Stop the node cleanly when the last window goes: flushes the
            // store and unbinds transports instead of relying on exit.
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if let Some(session) = window.state::<commands::AppState>().take() {
                    session.stop();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
