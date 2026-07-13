#!/usr/bin/env bash
# Generate the bindings, then run KommsCore's tests — unit tests plus the
# two-node e2e — against the host-built libkult_ffi. Needs only a Swift
# toolchain and Rust: no Xcode, simulator, or device.
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
"$root/apps/ios/scripts/generate-bindings.sh"

libdir="$root/target/release"
cd "$root/apps/ios/KommsCore"
case "$(uname -s)" in
    Darwin)
        export DYLD_LIBRARY_PATH="$libdir${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
        ;;
    *)
        export LD_LIBRARY_PATH="$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ;;
esac
swift test -Xlinker "-L$libdir" -Xlinker -lkult_ffi "$@"
