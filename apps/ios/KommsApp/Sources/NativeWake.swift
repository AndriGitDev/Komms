import KommsCore
import UIKit
import UserNotifications

/// Secret-free local preference; APNs device tokens never enter UserDefaults.
enum NativeWakePreferenceStore {
    private static let key = "komms.native-wake.profile"

    static func load() -> NativeWakePreference {
        NativeWakePreference(
            rawValue: UserDefaults.standard.string(forKey: key) ?? ""
        ) ?? .disabled
    }

    static func save(_ preference: NativeWakePreference) {
        UserDefaults.standard.set(preference.rawValue, forKey: key)
    }
}

/**
 Process-memory-only handoff between UIApplicationDelegate callbacks and the
 unlocked model. A token is never logged, put in notification userInfo,
 persisted by the shell, or passed to WorkManager-style metadata.
 */
@MainActor
final class NativeWakeBridge {
    static let shared = NativeWakeBridge()

    typealias WakeHandler = (@escaping (UIBackgroundFetchResult) -> Void) -> Void

    private var token: Data?
    private var tokenHandler: ((Data?) -> Void)?
    private var wakeHandler: WakeHandler?

    func install(
        tokenHandler: @escaping (Data?) -> Void,
        wakeHandler: @escaping WakeHandler
    ) {
        self.tokenHandler = tokenHandler
        self.wakeHandler = wakeHandler
        tokenHandler(token)
    }

    func updateToken(_ token: Data?) {
        let retained =
            NativeWakePreferenceStore.load() == .disabled ? nil : token
        self.token = retained
        tokenHandler?(retained)
    }

    func requestCurrentToken() {
        guard NativeWakePreferenceStore.load() != .disabled else {
            UIApplication.shared.unregisterForRemoteNotifications()
            token = nil
            tokenHandler?(nil)
            return
        }
        UIApplication.shared.registerForRemoteNotifications()
    }

    func receiveWake(completion: @escaping (UIBackgroundFetchResult) -> Void) {
        guard let wakeHandler else {
            completion(.noData)
            return
        }
        wakeHandler(completion)
    }
}

final class KommsAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [
            UIApplication.LaunchOptionsKey: Any
        ]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        if NativeWakePreferenceStore.load() != .disabled {
            application.registerForRemoteNotifications()
        }
        return true
    }

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        Task { @MainActor in NativeWakeBridge.shared.updateToken(deviceToken) }
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        Task { @MainActor in NativeWakeBridge.shared.updateToken(nil) }
    }

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        guard Self.isStaticWake(userInfo) else {
            completionHandler(.noData)
            return
        }
        Task { @MainActor in
            NativeWakeBridge.shared.receiveWake(completion: completionHandler)
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        Self.isVisibleStaticWake(notification.request.content.userInfo)
            ? [.banner, .sound]
            : []
    }

    static func isVisibleStaticWake(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard isStaticWake(userInfo),
              let aps = userInfo["aps"] as? [String: Any],
              let alert = aps["alert"] as? [String: Any]
        else {
            return false
        }
        return alert["title"] as? String == "Komms"
            && alert["body"] as? String == "New activity"
            && aps["sound"] as? String == "default"
    }

    static func isStaticWake(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard userInfo.keys.allSatisfy({ ($0 as? String) == "aps" }),
              let aps = userInfo["aps"] as? [String: Any]
        else {
            return false
        }
        let allowedAps = Set(["content-available", "alert", "sound"])
        guard Set(aps.keys).isSubset(of: allowedAps) else { return false }
        let contentAvailable = aps["content-available"] as? Int ?? 0
        let sound = aps["sound"] as? String
        let alert = aps["alert"] as? [String: Any]
        let alertKeys: Set<String> = alert.map { Set($0.keys) } ?? []
        guard alertKeys.isSubset(of: Set(["title", "body"])) else { return false }
        return NativeWakePolicy.acceptsStaticPayload(
            contentAvailable: contentAvailable,
            alertTitle: alert?["title"] as? String,
            alertBody: alert?["body"] as? String,
            sound: sound,
            applicationKeys: [])
    }
}
