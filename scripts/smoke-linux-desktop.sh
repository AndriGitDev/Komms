#!/usr/bin/env bash
set -euo pipefail

binary="${1:-apps/desktop/src-tauri/target/debug/komms-desktop}"
seconds="${KOMMS_LINUX_SMOKE_SECONDS:-10}"

if [[ ! -x "$binary" ]]; then
  echo "Linux desktop smoke binary is missing or not executable: $binary" >&2
  exit 1
fi

for command in timeout xvfb-run dbus-run-session; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Linux desktop smoke requires '$command'." >&2
    exit 1
  fi
done

set +e
timeout --kill-after=5s "$seconds" \
  xvfb-run -a dbus-run-session -- "$binary"
status=$?
set -e

if [[ "$status" -eq 124 ]]; then
  echo "Linux desktop launch smoke passed: the shell stayed alive for ${seconds}s."
  exit 0
fi

echo "Linux desktop launch smoke failed: the shell exited with status $status." >&2
exit "$status"
