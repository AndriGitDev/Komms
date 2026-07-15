// :core — the shell's entire testable behavior, as a plain JVM module.
//
// It compiles the UniFFI-generated Kotlin bindings (produced at build time
// from the workspace's `kult-ffi` crate — generated code is never committed)
// together with the session layer the Android UI drives. Tests run on the
// host JVM against the host-built `libkult_ffi`, so two full nodes can be
// driven end-to-end with no Android SDK, emulator, or device.

import java.time.Duration
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

// Pin the JVM dependency graph (gradle.lockfile), mirroring the cargo
// workspace's lockfile posture. Refresh with:
//   gradle :core:dependencies --write-locks
dependencyLocking { lockAllConfigurations() }

// Target Java 17 bytecode (what AGP consumes) from whatever JDK ≥ 17 runs
// the build — no pinned toolchain, so any modern JDK works.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(false) // generated bindings carry warnings
    }
}

// The cargo workspace this build is embedded in (apps/android → repo root).
val repoRoot = rootDir.resolve("../..").normalize()
val hostLibDir = repoRoot.resolve("target/release")
val bindingsDir = layout.buildDirectory.dir("generated/uniffi")

// Build the host cdylib. Cargo is its own incremental build system, so the
// task always runs and cargo decides what (if anything) to do.
val buildHostLibrary by tasks.registering(Exec::class) {
    description = "cargo build -p kult-ffi --release (host cdylib for JVM tests)"
    workingDir = repoRoot
    commandLine("cargo", "build", "-p", "kult-ffi", "--release")
    outputs.upToDateWhen { false }
}

// Generate the Kotlin bindings from the freshly built library, exactly as
// documented in kult-ffi's crate docs.
val generateBindings by tasks.registering(Exec::class) {
    description = "uniffi-bindgen generate --language kotlin"
    dependsOn(buildHostLibrary)
    workingDir = repoRoot
    val hostLibName = System.getProperty("os.name").lowercase().let {
        when {
            it.contains("mac") -> "libkult_ffi.dylib"
            it.contains("win") -> "kult_ffi.dll"
            else -> "libkult_ffi.so"
        }
    }
    commandLine(
        "cargo", "run", "-p", "kult-ffi", "--features", "bindgen",
        "--bin", "uniffi-bindgen", "--",
        "generate", "--library", "target/release/$hostLibName",
        "--language", "kotlin",
        "--out-dir", bindingsDir.get().asFile.absolutePath,
        "--no-format",
    )
    outputs.dir(bindingsDir)
    outputs.upToDateWhen { false }
}

sourceSets["main"].kotlin.srcDir(bindingsDir)
tasks.compileKotlin { dependsOn(generateBindings) }

dependencies {
    // `api`: the generated bindings' types (Contact, Message, Event, …) are
    // this module's public surface, and they need JNA to load the library.
    api(libs.jna)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit)
}

tasks.test {
    dependsOn(buildHostLibrary)
    // Where JNA finds the host-built libkult_ffi at test time.
    systemProperty("jna.library.path", hostLibDir.absolutePath)
    systemProperty("komms.repo.root", repoRoot.absolutePath)
    // The e2e test boots real nodes (Argon2id, QUIC on loopback) — give it
    // room, and show which scenario is running.
    timeout.set(Duration.ofMinutes(15))
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = false
    }
}
