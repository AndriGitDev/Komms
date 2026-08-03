#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
apk="${1:-$root/apps/android/app/build/outputs/apk/googleFree/debug/app-googleFree-debug.apk}"

if [[ ! -f "$apk" ]]; then
    printf 'Google-free APK not found: %s\n' "$apk" >&2
    exit 1
fi

if unzip -Z1 "$apk" | rg -qi '(^|/)(firebase|play-services)|firebase.*\.(properties|xml)$'; then
    printf 'Google-free APK contains a Firebase or Play Services resource.\n' >&2
    exit 1
fi

if unzip -p "$apk" 'classes*.dex' |
    strings |
    rg -qi 'com/google/firebase|FirebaseMessaging(Service)?|com/google/android/gms'; then
    printf 'Google-free APK contains Firebase, FCM, or Play Services bytecode.\n' >&2
    exit 1
fi

printf 'Google-free APK contains no Firebase, FCM, or Play Services code/resources.\n'
