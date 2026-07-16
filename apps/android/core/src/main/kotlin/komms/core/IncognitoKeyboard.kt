package komms.core

import uniffi.kult_ffi.IncognitoKeyboardPlatform
import uniffi.kult_ffi.IncognitoKeyboardPolicy
import uniffi.kult_ffi.incognitoKeyboardPolicy

/** Canonical always-on B15 promise rendered by the Android settings shell. */
fun androidIncognitoKeyboardPolicy(): IncognitoKeyboardPolicy =
    incognitoKeyboardPolicy(IncognitoKeyboardPlatform.ANDROID)
