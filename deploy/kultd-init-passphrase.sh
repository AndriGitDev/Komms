#!/bin/sh
set -eu

secret_file="${KULTD_PASSPHRASE_FILE:-/run/komms-secrets/passphrase}"

if [ -e "$secret_file" ]; then
    echo "kultd-init-passphrase: $secret_file already exists; refusing to replace it" >&2
    exit 1
fi

if [ ! -t 0 ]; then
    echo "kultd-init-passphrase: an interactive terminal is required" >&2
    exit 1
fi

restore_echo() {
    stty echo 2>/dev/null || true
}
trap restore_echo EXIT HUP INT TERM

printf 'New kultd store passphrase: ' >&2
stty -echo
IFS= read -r first
stty echo
printf '\nConfirm passphrase: ' >&2
stty -echo
IFS= read -r second
stty echo
printf '\n' >&2

if [ -z "$first" ]; then
    echo "kultd-init-passphrase: the passphrase must not be empty" >&2
    exit 1
fi
if [ "$first" != "$second" ]; then
    echo "kultd-init-passphrase: passphrases did not match" >&2
    exit 1
fi

umask 077
printf '%s' "$first" > "$secret_file"
unset first second
echo "Created owner-only secret file at $secret_file" >&2
