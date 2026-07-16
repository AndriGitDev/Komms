// The iOS shell's entry point: the gate until a session exists, the
// contact list afterwards. All behavior lives in KommsCore's `Session`
// (pinned by its e2e test); this app is UI only.

import KommsCore
import SwiftUI

@main
struct KommsApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = AppModel()
    @StateObject private var screenSecurity = ScreenSecurityController()

    var body: some Scene {
        WindowGroup {
            ZStack {
                Group {
                    if model.session == nil {
                        GateView().environmentObject(model)
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
            .onAppear { screenSecurity.update(scenePhase: scenePhase) }
            .onChange(of: scenePhase) { phase in
                screenSecurity.update(scenePhase: phase)
                if phase == .active {
                    Task { await model.refresh() }
                }
            }
        }
    }
}
