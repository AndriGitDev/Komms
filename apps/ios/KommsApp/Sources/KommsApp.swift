// The iOS shell's entry point: the gate until a session exists, the
// contact list afterwards. All behavior lives in KommsCore's `Session`
// (pinned by its e2e test); this app is UI only.

import KommsCore
import SwiftUI

@main
struct KommsApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            Group {
                if model.session == nil {
                    GateView().environmentObject(model)
                } else {
                    MainView().environmentObject(model)
                }
            }
            .preferredColorScheme(model.themePreference.colorScheme)
            .onChange(of: scenePhase) { phase in
                if phase == .active {
                    Task { await model.refresh() }
                }
            }
        }
    }
}
