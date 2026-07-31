import XCTest
@testable import KommsCore

final class NativeWakePolicyTests: XCTestCase {
    private func eligible(
        token: String = "token-a",
        preference: NativeWakePreference = .genericVisible,
        permission: NativeWakePermission = .granted,
        backgroundRefresh: Bool = true
    ) -> NativeWakeSnapshot {
        NativeWakeSnapshot(
            mode: "standard",
            gatewayCount: 1,
            preference: preference,
            permission: permission,
            backgroundRefreshAvailable: backgroundRefresh,
            tokenDigest: token,
            advertised: true)
    }

    func testTokenRotationAndAppLaunchRequireFreshCapabilities() {
        let old = eligible()
        XCTAssertEqual(
            NativeWakePolicy.decide(previous: old, current: eligible(token: "token-b")).action,
            .register)
        XCTAssertEqual(
            NativeWakePolicy.decide(previous: old, current: old, forceRefresh: true).action,
            .register)
        XCTAssertEqual(NativeWakePolicy.decide(previous: old, current: old).action, .none)
    }

    func testPermissionModeAndBackgroundRefreshRevokeUnavailableProfiles() {
        let old = eligible()
        XCTAssertEqual(
            NativeWakePolicy.decide(
                previous: old,
                current: eligible(permission: .denied)).action,
            .revoke)
        XCTAssertEqual(
            NativeWakePolicy.decide(
                previous: old,
                current: old.with(mode: "sovereign")).action,
            .revoke)
        XCTAssertEqual(
            NativeWakePolicy.decide(
                previous: old,
                current: eligible(
                    preference: .backgroundOnly,
                    permission: .notRequired,
                    backgroundRefresh: false)).action,
            .revoke)
    }

    func testOnlyStaticContentFreeAPNsPayloadsAreAccepted() {
        XCTAssertTrue(NativeWakePolicy.acceptsStaticPayload(
            contentAvailable: 1,
            alertTitle: nil,
            alertBody: nil,
            sound: nil,
            applicationKeys: []))
        XCTAssertTrue(NativeWakePolicy.acceptsStaticPayload(
            contentAvailable: 1,
            alertTitle: "Komms",
            alertBody: "New activity",
            sound: "default",
            applicationKeys: []))
        XCTAssertFalse(NativeWakePolicy.acceptsStaticPayload(
            contentAvailable: 1,
            alertTitle: "Komms",
            alertBody: "Message from Alice",
            sound: "default",
            applicationKeys: []))
        XCTAssertFalse(NativeWakePolicy.acceptsStaticPayload(
            contentAvailable: 1,
            alertTitle: nil,
            alertBody: nil,
            sound: nil,
            applicationKeys: ["sender"]))
    }

    func testForceQuitAndBackgroundRefreshLimitCollection() {
        XCTAssertTrue(NativeWakePolicy.canRunBackgroundCollection(
            backgroundRefreshAvailable: true,
            forceQuit: false))
        XCTAssertFalse(NativeWakePolicy.canRunBackgroundCollection(
            backgroundRefreshAvailable: true,
            forceQuit: true))
        XCTAssertFalse(NativeWakePolicy.canRunBackgroundCollection(
            backgroundRefreshAvailable: false,
            forceQuit: false))
    }
}

private extension NativeWakeSnapshot {
    func with(mode: String) -> NativeWakeSnapshot {
        var copy = self
        copy.mode = mode
        return copy
    }
}
