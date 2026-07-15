package komms.android

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.util.concurrent.atomic.AtomicInteger
import uniffi.kult_ffi.Event

/**
 * A minimal foreground service: it holds no logic — the node lives in
 * [NodeHolder] — but its notification keeps the process (and therefore the
 * delivery engine, listeners, and mailbox check-ins) alive while the app is
 * backgrounded.
 */
class NodeService : Service() {
    private val mentionListener: (Event) -> Unit = { event ->
        if (event is Event.MentionReceived) showPrivateMentionNotification()
    }

    override fun onCreate() {
        super.onCreate()
        NodeHolder.addListener(mentionListener)
    }

    override fun onDestroy() {
        NodeHolder.removeListener(mentionListener)
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_running))
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(ID, notification)
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun showPrivateMentionNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && !manager.areNotificationsEnabled()) return
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.mention_notification_preview))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
        try {
            manager.notify(NEXT_NOTIFICATION.getAndIncrement(), notification)
        } catch (_: SecurityException) {
            // Notification authorization remains controlled by MainActivity's
            // existing user-driven path; mention delivery never requests it.
        }
    }

    companion object {
        const val CHANNEL_ID = "komms-node"
        private const val ID = 1
        private val NEXT_NOTIFICATION = AtomicInteger(17_000)
    }
}
