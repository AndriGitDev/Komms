#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_in() {
    local directory="$1"
    shift
    printf '\n==> (%s) %s\n' "$directory" "$*"
    (cd "$directory" && "$@")
}

printf '%s\n' \
    "Komms operating-mode local journey gate" \
    "Evidence boundary: hermetic host/localhost and shell-contract tests only." \
    "This does not qualify distinct real NATs, external operators, mobile" \
    "background behavior, physical devices, or production defaults."

run_in "$root" cargo test -p kult-transport \
    provider_directory::tests::deterministic_clean_install_provider_journeys_remain_replaceable_and_optional \
    --lib -- --exact
run_in "$root" cargo test -p kult-transport \
    provider_directory::tests::removing_directory_configuration_disables_cached_defaults_without_erasing_manual_routes \
    --lib -- --exact
run_in "$root" cargo test -p kult-node --test discovery_e2e \
    standard_records_are_fixed_sealed_and_mailbox_only -- --exact
run_in "$root" cargo test -p kult-node --test first_contact_admission_e2e \
    unknown_sender_is_provisional_until_explicit_accept -- --exact
run_in "$root" cargo test -p kult-node --test internet_e2e \
    contact_by_connect_code_via_dht -- --exact
run_in "$root" cargo test -p kult-node --test internet_e2e \
    stale_pairing_hint_heals_only_via_authenticated_peer_update -- --exact
run_in "$root" cargo test -p kult-node --test mailbox_e2e \
    offline_recipient_via_relay_mailbox -- --exact
run_in "$root" cargo test -p kult-node --test rendezvous_e2e \
    provider_control_registration_lookup_and_source_merge_recover_a_route -- --exact
run_in "$root" cargo test -p kult-node --test backup_e2e \
    backup_restores_identity_and_rekeys_sessions -- --exact
run_in "$root" cargo test -p kult-ffi --test ffi_e2e \
    operating_mode_changes_preserve_identity_trust_history_and_queued_work -- --exact

desktop="$root/apps/desktop/src-tauri"
run_in "$desktop" cargo test --offline operating_mode

if command -v gradle >/dev/null 2>&1; then
    run_in "$root/apps/android" gradle :core:test -Pkomms.androidApp=false \
        --tests komms.core.NetworkSettingsTest
else
    printf '\nDEFERRED: Android shared-settings journey needs Gradle with JDK 17+.\n'
fi

if command -v swift >/dev/null 2>&1; then
    run_in "$root" "$root/apps/ios/scripts/test-core.sh" \
        --filter NetworkSettingsTests
else
    printf '\nDEFERRED: iOS shared-settings journey needs Swift 5.9+.\n'
fi

run_in "$root" git diff --check
printf '\nOperating-mode local journey gate passed. External qualification remains open.\n'
