# 13: Screen Security

B14 is shipped as an **always-on application-shell boundary**. It reduces
accidental disclosure through screenshots, recordings, app-switcher snapshots,
and recent/task previews where the operating system offers a relevant API. It is
not DRM and does not change Komms' end-to-end encryption or endpoint-compromise
limits.

## User promise

Protection starts before the encrypted store opens and cannot be disabled. It is
therefore not a sealed preference, does not enter `KKR6`, and never creates an
envelope, capability, notification, queue item, peer synchronization, or
transport work. `kult-node` owns the render-safe capability vocabulary;
RPC/CLI and UniFFI expose it so every shell describes the same promise.

| Platform | Capture prevention | Background/recent preview | Detection | Rapid lock |
|---|---|---|---|---|
| Android | Platform-enforced `FLAG_SECURE` | Platform-enforced `FLAG_SECURE` | Unavailable | Existing Lock action |
| iOS | Unavailable for universal still screenshots | Privacy shield before inactive/background snapshots | UIKit live-capture notification | Existing Lock action |
| Desktop | Best effort through Tauri native content protection | Best effort plus an inactive-window privacy shield | Unavailable | `Ctrl/Cmd+Shift+L` |

`platform-enforced` means Komms enables the supported OS API across its whole
surface. It does not mean a compromised OS, privileged malware, accessibility or
overlay abuse, or an external camera is defeated. `best-effort` means the request
may be ignored by the operating system, window server, compositor, capture tool,
or desktop environment.

## Platform behavior

### Android

Every declared activity inherits `SecureActivity`, which installs
`WindowManager.LayoutParams.FLAG_SECURE` before AppCompat restores or draws UI.
This includes create/unlock/restore, settings, QR, chat, group, note-to-self,
folder, label, icon, and verification surfaces. Android blocks compliant
screenshots and recordings and supplies a protected recent-task preview. Komms
does not claim a reliable callback for every blocked attempt.

### iOS

The root scene starts covered and becomes visible only while active and not
captured. `UIApplication.willResignActiveNotification` covers content before the
app-switcher snapshot; scene-phase changes provide a second lifecycle signal.
`UIScreen.capturedDidChangeNotification` covers the whole scene during live
recording or mirroring and removes the cover when capture ends.

iOS does not give applications a universal API to prevent still screenshots.
The settings screen says so explicitly. Capture notification may also arrive
after recording or mirroring begins; the shield is response and minimization,
not a retroactive guarantee.

### Desktop

The Tauri window requests native `contentProtected` behavior both in its checked
configuration and at setup. Support varies by OS and compositor, so this remains
best effort. Focus loss additionally places an opaque privacy shield over the
webview. `Ctrl+Shift+L` on Linux/Windows or `Cmd+Shift+L` on macOS immediately
uses the ordinary lock path: recording/review transients are discarded, the node
stops cleanly, session-backed render state is cleared, and the unlock gate
returns. The visible Lock button remains equivalent and documents the shortcut.

## Qualification

Automated coverage pins the shared `b14-screen-security-parity.json` contract in
`kult-node`, strict RPC/CLI, UniFFI, Android KommsCore, iOS KommsCore, and the
desktop command layer. Platform builds prove native source compatibility. Native
capture and snapshot behavior still requires real OS evidence:

1. **Android device/emulator:** visit every activity from the locked gate and an
   unlocked session; verify screenshot and `screenrecord` output is refused or
   blank, and recent tasks never contains Komms content.
2. **iOS device/simulator:** background from the gate, conversation, attachment
   review, QR, and settings; verify the app switcher contains only the privacy
   shield. Start screen recording/mirroring while active and verify the shield
   appears and clears. Take a still screenshot and verify the documented
   unsupported state remains truthful.
3. **Desktop OS/compositor matrix:** inspect task/recent previews and native
   screenshots on supported macOS, Windows, X11, and Wayland combinations;
   record unsupported combinations rather than upgrading the claim. Verify
   focus loss covers the webview and `Ctrl/Cmd+Shift+L` returns to a cleared gate
   immediately from conversations, modals, and media review.

Release qualification records the OS version, compositor/window server, capture
method, expected capability level, actual result, and whether the locked gate
contains any prior session content.
