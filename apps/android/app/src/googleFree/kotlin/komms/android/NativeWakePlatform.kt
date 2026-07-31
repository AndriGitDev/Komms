package komms.android

import android.content.Context

/**
 * Google-free builds neither link an FCM SDK nor advertise native-wake
 * capability. Ordinary direct, mailbox, LAN, mesh, and file paths remain.
 */
object NativeWakePlatform {
    fun supported(context: Context): Boolean {
        @Suppress("UNUSED_VARIABLE")
        val application = context.applicationContext
        return false
    }

    fun requestCurrentToken(context: Context, callback: (ByteArray?) -> Unit) {
        @Suppress("UNUSED_VARIABLE")
        val application = context.applicationContext
        callback(null)
    }
}
