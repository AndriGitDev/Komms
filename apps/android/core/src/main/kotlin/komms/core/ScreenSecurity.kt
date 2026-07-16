package komms.core

import uniffi.kult_ffi.ScreenSecurityPlatform
import uniffi.kult_ffi.ScreenSecurityPolicy
import uniffi.kult_ffi.screenSecurityPolicy

/** Canonical always-on B14 promise rendered by the Android settings shell. */
fun androidScreenSecurityPolicy(): ScreenSecurityPolicy =
    screenSecurityPolicy(ScreenSecurityPlatform.ANDROID)
