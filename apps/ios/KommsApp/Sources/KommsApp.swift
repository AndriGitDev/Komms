// The iOS shell's entry point: the gate until a session exists, the
// contact list afterwards. All behavior lives in KommsCore's `Session`
// (pinned by its e2e test); this app is UI only.

import Foundation
import KommsCore
import SwiftUI

@main
struct KommsApp: App {
    @UIApplicationDelegateAdaptor(KommsAppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = AppModel()
    @StateObject private var screenSecurity = ScreenSecurityController()
    @AppStorage("komms.locale") private var localePreference = "system"

    var body: some Scene {
        WindowGroup {
            ZStack {
                Group {
                    if model.session == nil {
                        GateView().environmentObject(model)
                    } else if model.requiresRecoveryAuthorityExport {
                        RecoveryAuthorityView().environmentObject(model)
                    } else {
                        MainView().environmentObject(model)
                    }
                }
                .accessibilityHidden(screenSecurity.isObscured)

                if screenSecurity.isObscured {
                    ScreenPrivacyShield(captureDetected: screenSecurity.captureDetected)
                        .transition(.identity)
                        .zIndex(1000)
                }
            }
            .preferredColorScheme(model.themePreference.colorScheme)
            .environment(
                \.locale,
                Locale(
                    identifier: localePreference == "system"
                        ? L10n.activeLocale
                        : localePreference
                )
            )
            .tint(ThemePalette.accent)
            .background(ThemePalette.background.ignoresSafeArea())
            .onAppear { screenSecurity.update(scenePhase: scenePhase) }
            .onChange(of: scenePhase) { phase in
                screenSecurity.update(scenePhase: phase)
                if phase == .active {
                    Task {
                        await model.nativeWakeBecameActive()
                        await model.refresh()
                    }
                }
            }
        }
    }
}
