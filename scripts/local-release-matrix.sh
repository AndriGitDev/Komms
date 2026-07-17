#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_seconds="${KOMMS_FUZZ_SECONDS:-60}"
android_required="${KOMMS_REQUIRE_ANDROID_APP:-0}"
ios_required="${KOMMS_REQUIRE_IOS_APP:-0}"

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run_in() {
    local directory="$1"
    shift
    printf '\n==> (%s) %s\n' "$directory" "$*"
    (cd "$directory" && "$@")
}

export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

run_in "$root" cargo fmt --all -- --check
run_in "$root" cargo clippy --workspace --all-targets --all-features
run_in "$root" cargo test --workspace --all-features
run_in "$root" cargo build -p kult-crypto -p kult-protocol --no-default-features
run_in "$root" cargo deny check

desktop="$root/apps/desktop/src-tauri"
run_in "$desktop" cargo fmt --all -- --check
run_in "$desktop" cargo clippy --all-targets --all-features
run_in "$desktop" cargo test --all-features
run_in "$desktop" cargo deny check

if command -v gradle >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    run_in "$root/apps/android" gradle :core:build -Pkomms.androidApp=false --rerun-tasks
else
    printf '\nDEFERRED: Android host-core gate needs JDK 17+ and Gradle.\n'
    if [[ "$android_required" == "1" ]]; then
        exit 1
    fi
fi

android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -n "$android_sdk" && -d "$android_sdk" ]] && command -v cargo-ndk >/dev/null 2>&1; then
    run_in "$root/apps/android" gradle :app:assembleDebug :app:lintDebug -Pkomms.androidApp=true
else
    printf '\nDEFERRED: Android APK/lint gate needs Android SDK/NDK and cargo-ndk.\n'
    if [[ "$android_required" == "1" ]]; then
        exit 1
    fi
fi

if command -v swift >/dev/null 2>&1; then
    if [[ -d /Applications/Xcode.app ]]; then
        export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
        export PATH="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"
    fi
    run_in "$root" "$root/apps/ios/scripts/test-core.sh"
else
    printf '\nDEFERRED: iOS host-core gate needs Swift 5.9+.\n'
    if [[ "$ios_required" == "1" ]]; then
        exit 1
    fi
fi

if [[ -d /Applications/Xcode.app ]] && command -v xcodegen >/dev/null 2>&1; then
    run_in "$root" "$root/apps/ios/scripts/build-xcframework.sh"
    run_in "$root/apps/ios/KommsApp" xcodegen generate
    run_in "$root/apps/ios/KommsApp" xcodebuild -quiet \
        -project KommsApp.xcodeproj -scheme KommsApp -sdk iphonesimulator \
        -configuration Debug CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=YES \
        ARCHS=arm64 build
else
    printf '\nDEFERRED: iOS app gate needs full Xcode and XcodeGen.\n'
    if [[ "$ios_required" == "1" ]]; then
        exit 1
    fi
fi

crypto_fuzz=(
    envelope_decode handshake_decode bundle_decode mnemonic_decode
    attachment_chunk_open device_prekey_decode call_media_open
)
for target in "${crypto_fuzz[@]}"; do
    run_in "$root/crates/kult-crypto" cargo +nightly fuzz run "$target" -- \
        "-max_total_time=$fuzz_seconds"
done

protocol_fuzz=(
    protocol_envelope_decode bundle_import reassembler_insert content_decode
    capability_decode attachment_manifest_decode attachment_bulk_decode
    attachment_ranges mention_decode edit_decode ephemeral_decode poll_decode
    group_authority_decode device_sync_bundle_decode call_control_decode
)
for target in "${protocol_fuzz[@]}"; do
    run_in "$root/crates/kult-protocol" cargo +nightly fuzz run "$target" -- \
        "-max_total_time=$fuzz_seconds"
done

run_in "$root" git diff --check
run_in "$root" git status --short
printf '\nLocal release matrix passed. Review any DEFERRED gates above before publication.\n'
