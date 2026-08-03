import SwiftUI
import UIKit

/// Always-on B14 lifecycle boundary for the complete iOS scene.
///
/// iOS offers no universal still-screenshot block. Komms instead covers the
/// scene before inactive/background snapshots and while UIKit reports live
/// capture (recording, mirroring, or compatible external display capture).
@MainActor
final class ScreenSecurityController: ObservableObject {
    @Published private(set) var isObscured = true
    @Published private(set) var captureDetected = false

    private var sceneIsActive = false
    private var observers: [NSObjectProtocol] = []
    private let center: NotificationCenter

    init(center: NotificationCenter = .default) {
        self.center = center
        captureDetected = UIScreen.main.isCaptured
        observers.append(center.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.setSceneActive(false) }
        })
        observers.append(center.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.setSceneActive(true) }
        })
        observers.append(center.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.setCaptured(UIScreen.main.isCaptured)
            }
        })
        recompute()
    }

    deinit {
        observers.forEach(center.removeObserver)
    }

    func update(scenePhase: ScenePhase) {
        setSceneActive(scenePhase == .active)
    }

    private func setSceneActive(_ active: Bool) {
        sceneIsActive = active
        recompute()
    }

    private func setCaptured(_ captured: Bool) {
        captureDetected = captured
        recompute()
    }

    private func recompute() {
        isObscured = !sceneIsActive || captureDetected
    }
}

struct ScreenPrivacyShield: View {
    let captureDetected: Bool

    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground).ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 44))
                    .accessibilityHidden(true)
                Text(L10n.text("ui_komms_is_protected"))
                    .font(.headline)
                Text(L10n.text(captureDetected
                     ? "screen_shield_capture_message"
                     : "screen_shield_inactive_message"))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding(32)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(L10n.text(captureDetected
            ? "screen_shield_capture_accessibility"
            : "screen_shield_inactive_accessibility"))
    }
}
