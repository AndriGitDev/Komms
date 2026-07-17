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

use tauri::{Emitter, Manager};

/// Build and run the Tauri application (called from `main`).
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::default())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                // Best effort by Tauri contract: support depends on the OS,
                // window server, and compositor, so failure must not prevent
                // the user from reaching the always-available rapid lock.
                let _ = window.set_content_protected(true);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::screen_security_policy,
            commands::incognito_keyboard_policy,
            commands::unlock,
            commands::restore,
            commands::lock,
            commands::status,
            commands::device_id,
            commands::linked_devices,
            commands::message_device_deliveries,
            commands::rename_linked_device,
            commands::revoke_linked_device,
            commands::begin_device_link,
            commands::accept_device_link,
            commands::device_link_confirmation_code,
            commands::approve_device_link,
            commands::complete_device_link,
            commands::export_device_sync,
            commands::import_device_sync,
            commands::format_text,
            commands::address_qr,
            commands::my_bundle,
            commands::add_contact,
            commands::add_contact_by_address,
            commands::contacts,
            commands::assess_contact_name,
            commands::rename_contact,
            commands::messages,
            commands::send,
            commands::send_disappearing,
            commands::edit_message,
            commands::send_recorded_audio,
            commands::send_group_recorded_audio,
            commands::audio_carrier_explanation,
            commands::attachment_carrier_explanation,
            commands::begin_image_edit,
            commands::update_image_edit,
            commands::discard_image_edit,
            commands::send_image_edit,
            commands::send_confirmed_attachment,
            commands::send_view_once_attachment,
            commands::send_group_view_once_attachment,
            commands::attachments,
            commands::accept_attachment,
            commands::reject_attachment,
            commands::cancel_attachment,
            commands::pause_attachment,
            commands::resume_attachment,
            commands::export_attachment,
            commands::consume_view_once_attachment,
            commands::open_attachment,
            commands::attachment_preview,
            commands::attachment_audio,
            commands::attachment_image,
            commands::schedule,
            commands::schedule_group,
            commands::scheduled_messages,
            commands::edit_scheduled,
            commands::cancel_scheduled,
            commands::note_to_self_id,
            commands::theme,
            commands::set_theme,
            commands::custom_icon,
            commands::set_custom_icon_from_path,
            commands::set_bundled_custom_icon,
            commands::clear_custom_icon,
            commands::custom_icon_usage,
            commands::create_folder,
            commands::folders,
            commands::folder,
            commands::rename_folder,
            commands::reorder_folders,
            commands::folder_delete_assignment_count,
            commands::delete_folder,
            commands::move_to_folder,
            commands::unfile_conversation,
            commands::folder_membership,
            commands::conversation_folder,
            commands::folder_conversations,
            commands::stale_folders,
            commands::cleanup_stale_folder,
            commands::create_label,
            commands::labels,
            commands::label,
            commands::update_label,
            commands::label_delete_assignment_count,
            commands::delete_label,
            commands::assign_label,
            commands::unassign_label,
            commands::label_membership,
            commands::labels_for_conversation,
            commands::stale_labels,
            commands::cleanup_stale_label,
            commands::filter_labels,
            commands::pin_conversation,
            commands::unpin_conversation,
            commands::pin_state,
            commands::pins,
            commands::reorder_pins,
            commands::stale_pins,
            commands::cleanup_stale_pin,
            commands::pin_conversations,
            commands::note_to_self_messages,
            commands::send_note_to_self,
            commands::create_group,
            commands::groups,
            commands::group_messages,
            commands::send_group,
            commands::send_group_disappearing,
            commands::edit_group_message,
            commands::group_mention_capability,
            commands::send_group_mention,
            commands::create_group_poll,
            commands::group_polls,
            commands::vote_group_poll,
            commands::close_group_poll,
            commands::moderate_group_poll_close,
            commands::group_authority,
            commands::upgrade_group_authority,
            commands::rename_group,
            commands::set_group_role,
            commands::transfer_group_owner,
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
            if let tauri::WindowEvent::Focused(focused) = event {
                let _ = window.emit("screen-security-focus", *focused);
            }
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
