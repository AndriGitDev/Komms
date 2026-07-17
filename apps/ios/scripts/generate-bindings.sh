#!/usr/bin/env bash
# Build the host kult-ffi library and generate the Swift bindings into the
# KommsCore package — at build time, from the workspace's crate; generated
# code is never committed (the same posture as the Android build).
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
core="$root/apps/ios/KommsCore"

case "$(uname -s)" in
    Darwin) lib="libkult_ffi.dylib" ;;
    *) lib="libkult_ffi.so" ;;
esac

cargo build --manifest-path "$root/Cargo.toml" -p kult-ffi --release

out="$core/.bindings"
rm -rf "$out"
cargo run --release --manifest-path "$root/Cargo.toml" -p kult-ffi --features bindgen \
    --bin uniffi-bindgen -- \
    generate --library "$root/target/release/$lib" \
    --language swift --out-dir "$out" --no-format

swift_dir="$core/Sources/KommsCore/Generated"
header_dir="$core/Sources/kult_ffiFFI/include"
mkdir -p "$swift_dir" "$header_dir"
cp "$out/kult_ffi.swift" "$swift_dir/"
cp "$out/kult_ffiFFI.h" "$header_dir/"
# uniffi's own modulemap targets Xcode's conventions (`use "Darwin"`);
# SwiftPM wants a plain umbrella module that is identical on Linux and macOS.
cat >"$header_dir/module.modulemap" <<'EOF'
module kult_ffiFFI {
    header "kult_ffiFFI.h"
    export *
}
EOF
rm -rf "$out"

echo "bindings generated into $core"
