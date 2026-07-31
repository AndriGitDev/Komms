package komms.android

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging

/** Google Play flavor token boundary; configuration is injected at build time. */
object NativeWakePlatform {
    fun supported(context: Context): Boolean = firebaseApp(context) != null

    fun requestCurrentToken(context: Context, callback: (ByteArray?) -> Unit) {
        if (firebaseApp(context) == null) {
            callback(null)
            return
        }
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            val token = task.result?.takeIf { task.isSuccessful && it.isNotEmpty() }
            callback(token?.toByteArray(Charsets.UTF_8))
        }
    }

    private fun firebaseApp(context: Context): FirebaseApp? {
        val existing = FirebaseApp.getApps(context)
            .firstOrNull { it.name == FirebaseApp.DEFAULT_APP_NAME }
        if (existing != null) return existing
        if (
            BuildConfig.FCM_APPLICATION_ID.isEmpty() ||
            BuildConfig.FCM_PROJECT_ID.isEmpty() ||
            BuildConfig.FCM_API_KEY.isEmpty() ||
            BuildConfig.FCM_SENDER_ID.isEmpty()
        ) {
            return null
        }
        val options = FirebaseOptions.Builder()
            .setApplicationId(BuildConfig.FCM_APPLICATION_ID)
            .setProjectId(BuildConfig.FCM_PROJECT_ID)
            .setApiKey(BuildConfig.FCM_API_KEY)
            .setGcmSenderId(BuildConfig.FCM_SENDER_ID)
            .build()
        return FirebaseApp.initializeApp(context, options)
    }
}
