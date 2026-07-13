// Komms Android (application A2): its own Gradle build, deliberately outside
// the core cargo workspace — the Android/Gradle dependency tree never touches
// the core crates' lockfile or cargo-deny surface. The core is reached only
// through `kult-ffi`, built from source in this repository.

pluginManagement {
    repositories {
        gradlePluginPortal {
            content { excludeGroupByRegex("com\\.android.*") }
        }
        // Only the Android Gradle Plugin comes from Google; everything else
        // resolves from the plugin portal / Maven Central so the :core-only
        // build (no Android SDK) never needs Google's repository at all.
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.google\\.testing\\..*")
            }
        }
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.google\\.android\\..*")
            }
        }
    }
}

rootProject.name = "komms-android"

include(":core")

// The :app module needs an Android SDK and Google's Maven repository; the
// :core module (generated bindings + session layer + the e2e test) is plain
// JVM and needs neither. Skip :app honestly when no SDK is available instead
// of failing the whole build. Override with -Pkomms.androidApp=true/false.
val androidApp = providers.gradleProperty("komms.androidApp").orNull
val hasSdk = System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null ||
    file("local.properties").let { it.exists() && it.readText().contains("sdk.dir") }
if (androidApp == "true" || (androidApp != "false" && hasSdk)) {
    include(":app")
}
