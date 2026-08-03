package komms.android

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import komms.core.NativeWakePolicy

/**
 * Receives only the gateway's two static content-free FCM shapes. Message
 * data, sender labels, timestamps, and delivery-state claims are rejected.
 */
class KommsFirebaseMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        NativeWakeManager.updateToken(this, token.toByteArray(Charsets.UTF_8))
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val notification = message.notification
        if (
            !NativeWakePolicy.acceptsStaticPayload(
                data = message.data,
                notificationTitle = notification?.title,
                notificationBody = notification?.body,
            )
        ) {
            return
        }
        NativeWakeManager.handleWake(this)
    }
}
