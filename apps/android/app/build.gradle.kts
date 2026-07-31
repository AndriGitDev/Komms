// :app — the Android shell. UI only: every behavior lives in :core (tested
// on the JVM); this module is activities, layouts, the camera QR scanner,
// and the cargo-ndk invocation that puts libkult_ffi.so into the APK.

import java.util.Properties
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

// Release signing is scaffold-only: provide apps/android/keystore.properties
// (git-ignored; keys storeFile, storePassword, keyAlias, keyPassword) or the
// KOMMS_ANDROID_KEYSTORE* environment variables. Absent both, release builds
// stay unsigned and every debug/CI flow is unaffected. No keystore lives in
// this repository.
val keystoreProperties = Properties().apply {
    val file = rootDir.resolve("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

fun signingValue(property: String, env: String): String? =
    keystoreProperties.getProperty(property) ?: System.getenv(env)

val releaseStore = signingValue("storeFile", "KOMMS_ANDROID_KEYSTORE")
val nativeWakeProperties = Properties().apply {
    val file = rootDir.resolve("native-wake.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

fun nativeWakeValue(property: String, env: String): String =
    nativeWakeProperties.getProperty(property) ?: System.getenv(env).orEmpty()

fun buildString(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "komms.android"
    compileSdk = 35

    defaultConfig {
        // Matches the desktop app's bundle identifier family.
        applicationId = "is.andri.komms"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        // Plain 0.3.0 to match the workspace, desktop, and iOS version
        // family exactly (Apple version strings cannot carry a suffix);
        // alpha status is conveyed by the 0.x major and release notes.
        versionName = "0.3.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    if (releaseStore != null) {
        signingConfigs.create("release") {
            storeFile = rootDir.resolve(releaseStore)
            storePassword = signingValue("storePassword", "KOMMS_ANDROID_KEYSTORE_PASSWORD")
            keyAlias = signingValue("keyAlias", "KOMMS_ANDROID_KEY_ALIAS")
            keyPassword = signingValue("keyPassword", "KOMMS_ANDROID_KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            // No minification: this is an alpha, and an auditable APK
            // (classes map 1:1 to this source tree) beats a smaller one.
            isMinifyEnabled = false
            if (releaseStore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    flavorDimensions += "distribution"
    productFlavors {
        create("play") {
            dimension = "distribution"
            buildConfigField("boolean", "NATIVE_WAKE_SUPPORTED", "true")
            buildConfigField(
                "String",
                "FCM_APPLICATION_ID",
                buildString(nativeWakeValue("applicationId", "KOMMS_FCM_APPLICATION_ID")),
            )
            buildConfigField(
                "String",
                "FCM_PROJECT_ID",
                buildString(nativeWakeValue("projectId", "KOMMS_FCM_PROJECT_ID")),
            )
            buildConfigField(
                "String",
                "FCM_API_KEY",
                buildString(nativeWakeValue("apiKey", "KOMMS_FCM_API_KEY")),
            )
            buildConfigField(
                "String",
                "FCM_SENDER_ID",
                buildString(nativeWakeValue("senderId", "KOMMS_FCM_SENDER_ID")),
            )
        }
        create("googleFree") {
            dimension = "distribution"
            buildConfigField("boolean", "NATIVE_WAKE_SUPPORTED", "false")
        }
    }
    buildFeatures { buildConfig = true }
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
    implementation(libs.androidx.work.runtime)
    add("playImplementation", libs.firebase.messaging)

    testImplementation(libs.junit)
}
