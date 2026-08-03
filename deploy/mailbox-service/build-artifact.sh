#!/bin/sh
set -eu
umask 077

revision=${1:-$(git rev-parse HEAD)}
destination=${2:-dist/mailbox-service}

if [ "${#revision}" -ne 40 ]; then
    echo "revision must be one complete 40-character lowercase Git object id" >&2
    exit 2
fi
case "$revision" in
    *[!0-9a-f]*)
        echo "revision must be one complete 40-character lowercase Git object id" >&2
        exit 2
        ;;
esac

if [ "$(uname -s)" != Linux ]; then
    echo "mailbox-service deployment artifacts must be built on Linux" >&2
    exit 2
fi
if [ "$(git rev-parse HEAD)" != "$revision" ]; then
    echo "revision must equal the checked-out HEAD" >&2
    exit 2
fi
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "deployment artifacts require a clean worktree" >&2
    exit 2
fi

source_date_epoch=$(git show -s --format=%ct "$revision")
target=$(rustc -vV | sed -n 's/^host: //p')
artifact_dir="$destination/$revision/$target"
if [ -e "$artifact_dir" ] || [ -e "$artifact_dir.tar.gz" ]; then
    echo "artifact destination already exists" >&2
    exit 2
fi

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export KOMMS_SOURCE_REVISION="$revision"
export LC_ALL=C
export SOURCE_DATE_EPOCH="$source_date_epoch"
export TZ=UTC
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none"

cargo build --locked --release --package kult-mailbox
mkdir -p "$artifact_dir"
install -m 0755 target/release/kult-mailbox "$artifact_dir/kult-mailbox"
sha256sum "$artifact_dir/kult-mailbox" > "$artifact_dir/SHA256SUMS"

rustc_version=$(rustc --version)
cat > "$artifact_dir/provenance.json" <<EOF
{
  "schema": "komms-mailbox-artifact-provenance/1",
  "source_revision": "$revision",
  "source_date_epoch": $source_date_epoch,
  "target": "$target",
  "rustc": "$rustc_version",
  "cargo_locked": true
}
EOF

tar --sort=name \
    --mtime="@$source_date_epoch" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$artifact_dir" \
    -cf "$artifact_dir.tar" \
    SHA256SUMS kult-mailbox provenance.json
gzip -n "$artifact_dir.tar"
sha256sum "$artifact_dir.tar.gz" > "$artifact_dir.tar.gz.sha256"
