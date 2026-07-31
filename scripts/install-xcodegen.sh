#!/usr/bin/env bash
set -euo pipefail

version="2.45.4"
archive_sha256="090ec29491aad50aec10631bf6e62253fed733c50f3aab0f5ffc86bc170bdbef"
destination="${1:?usage: install-xcodegen.sh DESTINATION}"

if [[ -e "$destination" ]]; then
    echo "XcodeGen destination must not already exist: $destination" >&2
    exit 2
fi

download_dir="$(mktemp -d "${TMPDIR:-/tmp}/komms-xcodegen.XXXXXX")"
trap 'rm -rf -- "$download_dir"' EXIT
archive="$download_dir/xcodegen.zip"
extracted="$download_dir/extracted"

curl \
    --proto '=https' \
    --tlsv1.2 \
    --fail \
    --location \
    --silent \
    --show-error \
    "https://github.com/yonaskolb/XcodeGen/releases/download/$version/xcodegen.zip" \
    --output "$archive"
printf '%s  %s\n' "$archive_sha256" "$archive" | shasum -a 256 --check
mkdir -p "$extracted"
ditto -x -k "$archive" "$extracted"

mkdir -p "$destination"
cp -R "$extracted/xcodegen/bin" "$destination/"
cp -R "$extracted/xcodegen/share" "$destination/"
chmod 0755 "$destination/bin/xcodegen"

installed="$("$destination/bin/xcodegen" --version)"
if [[ "$installed" != "Version: $version" ]]; then
    echo "Unexpected XcodeGen version: $installed" >&2
    exit 2
fi
printf 'Installed XcodeGen %s with verified SHA-256.\n' "$version"
