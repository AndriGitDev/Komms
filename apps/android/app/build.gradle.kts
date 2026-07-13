// :app — the Android shell. UI only: every behavior lives in :core (tested
// on the JVM); this module is activities, layouts, the camera QR scanner,
// and the cargo-ndk invocation that puts libkult_ffi.so into the APK.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// The cargo workspace this build is embedded in (apps/android → repo root).
val repoRoot = rootDir.resolve("../..").normalize()
val rustJniLibs = layout.buildDirectory.dir("rustJniLibs")

// Which ABIs to build the Rust core for. arm64-v8a covers essentially all
// real phones; x86_64 covers the emulator. Override with
// -Pkomms.abis=arm64-v8a,armeabi-v7a,x86_64 for a wider release build.
val abis = (findProperty("komms.abis") as String? ?: "arm64-v8a,x86_64")
    .split(',').map { it.trim() }.filter { it.isNotEmpty() }

// Cross-compile `kult-ffi` with cargo-ndk (needs `cargo install cargo-ndk`
// and `rustup target add aarch64-linux-android x86_64-linux-android`).
// Cargo is its own incremental build system, so the task always runs.
val cargoNdk by tasks.registering(Exec::class) {
    description = "cargo ndk build --release -p kult-ffi (Android .so files)"
    workingDir = repoRoot
    val args = mutableListOf("ndk", "--platform", "26")
    for (abi in abis) args += listOf("-t", abi)
    args += listOf(
        "-o", rustJniLibs.get().asFile.absolutePath,
        "build", "--release", "-p", "kult-ffi",
    )
    commandLine("cargo", *args.toTypedArray())
    outputs.dir(rustJniLibs)
    outputs.upToDateWhen { false }
}

android {
    namespace = "komms.android"
    compileSdk = 35

    defaultConfig {
        // Matches the desktop app's bundle identifier family.
        applicationId = "is.andri.komms"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-alpha"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            // No minification: this is an alpha, and an auditable APK
            // (classes map 1:1 to this source tree) beats a smaller one.
            isMinifyEnabled = false
        }
    }

    sourceSets["main"].jniLibs.srcDir(rustJniLibs)
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// The Rust libraries must exist before jniLibs are merged into the APK.
tasks.whenTaskAdded {
    if (name.contains("JniLibFolders")) dependsOn(cargoNdk)
}

dependencies {
    // :core brings the generated bindings; swap its desktop JNA jar for
    // the Android AAR (same classes plus libjnidispatch.so per ABI).
    implementation(project(":core")) {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
    implementation(variantOf(libs.jna) { artifactType("aar") })

    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.recyclerview)
    // QR: CameraX drives the camera; ZXing core (pure Java, no Google
    // Play Services / ML Kit) does the decoding and the encoding.
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.core)
}
