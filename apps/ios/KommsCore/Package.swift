// swift-tools-version:5.9

// KommsCore — the iOS shell's entire testable behavior, as a Swift package.
//
// It compiles the UniFFI-generated Swift bindings (produced at build time
// from the workspace's `kult-ffi` crate by ../scripts/generate-bindings.sh —
// generated code is never committed) together with the session layer the
// SwiftUI app drives. Tests run on the host (Linux or macOS) against the
// host-built `libkult_ffi`, so two full nodes can be driven end-to-end with
// no Xcode, simulator, or device — see ../scripts/test-core.sh.

import PackageDescription

let package = Package(
    name: "KommsCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "KommsCore", targets: ["KommsCore"])
    ],
    targets: [
        // The generated C header for the Rust library, as a Clang module the
        // generated Swift imports. Symbols come from `libkult_ffi` itself:
        // the test script links the host cdylib; an app links the
        // static-library xcframework (../scripts/build-xcframework.sh).
        .target(name: "kult_ffiFFI"),
        .target(name: "KommsCore", dependencies: ["kult_ffiFFI"]),
        .testTarget(name: "KommsCoreTests", dependencies: ["KommsCore"]),
    ]
)
