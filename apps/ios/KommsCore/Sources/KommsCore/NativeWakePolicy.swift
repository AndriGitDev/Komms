import Foundation

/// Recipient-selected static APNs profile.
public enum NativeWakePreference: String, Codable, Sendable {
    case disabled
    case backgroundOnly
    case genericVisible
}

/// Alert authorization relevant to the visible profile.
public enum NativeWakePermission: Equatable, Sendable {
    case notRequired
    case granted
    case denied
}

/// Platform action required after one lifecycle transition.
public enum NativeWakeAction: Equatable, Sendable {
    case none
    case register
    case revoke
}

/// Secret-free facts used by the iOS lifecycle decision table.
public struct NativeWakeSnapshot: Equatable, Sendable {
    public var mode: String
    public var gatewayCount: Int
    public var preference: NativeWakePreference
    public var permission: NativeWakePermission
    public var backgroundRefreshAvailable: Bool
    public var tokenDigest: String?
    public var advertised: Bool

    public init(
        mode: String,
        gatewayCount: Int,
        preference: NativeWakePreference,
        permission: NativeWakePermission,
        backgroundRefreshAvailable: Bool,
        tokenDigest: String?,
        advertised: Bool
    ) {
        self.mode = mode
        self.gatewayCount = gatewayCount
        self.preference = preference
        self.permission = permission
        self.backgroundRefreshAvailable = backgroundRefreshAvailable
        self.tokenDigest = tokenDigest
        self.advertised = advertised
    }
}

/// One bounded platform decision.
public struct NativeWakeDecision: Equatable, Sendable {
    public var action: NativeWakeAction
    public var advertise: Bool

    public init(action: NativeWakeAction, advertise: Bool) {
        self.action = action
        self.advertise = advertise
    }
}

/// Pure lifecycle rules shared by the iOS app and host tests.
public enum NativeWakePolicy {
    public static func decide(
        previous: NativeWakeSnapshot?,
        current: NativeWakeSnapshot,
        forceRefresh: Bool = false
    ) -> NativeWakeDecision {
        precondition(["standard", "private", "sovereign"].contains(current.mode))
        let permissionAllows =
            current.preference != .genericVisible || current.permission == .granted
        let executionAllows =
            current.preference != .backgroundOnly || current.backgroundRefreshAvailable
        let eligible =
            current.mode != "sovereign"
            && (1...4).contains(current.gatewayCount)
            && current.preference != .disabled
            && current.tokenDigest != nil
            && permissionAllows
            && executionAllows
        guard eligible else {
            return NativeWakeDecision(
                action: previous?.advertised == true || current.advertised ? .revoke : .none,
                advertise: false)
        }
        let changed =
            previous == nil
            || previous?.tokenDigest != current.tokenDigest
            || previous?.preference != current.preference
            || previous?.mode != current.mode
            || previous?.gatewayCount != current.gatewayCount
            || previous?.advertised != true
        return NativeWakeDecision(
            action: changed || forceRefresh ? .register : .none,
            advertise: true)
    }

    /// Accept only the two static content-free APNs dictionaries.
    public static func acceptsStaticPayload(
        contentAvailable: Int,
        alertTitle: String?,
        alertBody: String?,
        sound: String?,
        applicationKeys: Set<String>
    ) -> Bool {
        guard contentAvailable == 1, applicationKeys.isEmpty else { return false }
        if alertTitle == nil && alertBody == nil && sound == nil { return true }
        return alertTitle == "Komms"
            && alertBody == "New activity"
            && sound == "default"
    }

    /// iOS does not execute background work after force-quit and may suppress
    /// it when Background App Refresh is disabled.
    public static func canRunBackgroundCollection(
        backgroundRefreshAvailable: Bool,
        forceQuit: Bool
    ) -> Bool {
        backgroundRefreshAvailable && !forceQuit
    }
}
