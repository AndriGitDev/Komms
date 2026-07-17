#!/usr/bin/env bash
# macOS only: cross-compile kult-ffi as static libraries for iOS device and
# simulator and assemble apps/ios/KultFFI.xcframework, which the app target
# links. The `kult_ffiFFI` Clang module itself comes from the KommsCore
# package (generated header) — the xcframework carries only the symbols.
#
# Prerequisites: Xcode command-line tools and
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "xcframeworks can only be assembled on macOS" >&2
    exit 1
fi

root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="$root/apps/ios/KultFFI.xcframework"

# Rust's Apple linker otherwise inherits the installed SDK's current minimum
# (and can silently produce an archive newer than the app's declared floor).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

# Keep the generated header/modulemap in step with the libraries. Scope the
# full Xcode macOS SDK to this host build; the iOS cross-builds below select
# their own SDKs through rustc and must not inherit this sysroot.
host_clang="$(xcrun --sdk macosx --find clang)"
host_sdk="$(xcrun --sdk macosx --show-sdk-path)"
CC="$host_clang" SDKROOT="$host_sdk" "$root/apps/ios/scripts/generate-bindings.sh"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build --manifest-path "$root/Cargo.toml" -p kult-ffi --release \
        --target "$target"
done

# One fat simulator library (arm64 + x86_64); the device slice stays thin.
simfat="$root/target/libkult_ffi-ios-sim.a"
lipo -create \
    "$root/target/aarch64-apple-ios-sim/release/libkult_ffi.a" \
    "$root/target/x86_64-apple-ios/release/libkult_ffi.a" \
    -output "$simfat"

rm -rf "$out"
xcodebuild -create-xcframework \
    -library "$root/target/aarch64-apple-ios/release/libkult_ffi.a" \
    -library "$simfat" \
    -output "$out"

echo "assembled $out"
