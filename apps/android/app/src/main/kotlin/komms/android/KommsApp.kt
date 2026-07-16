package komms.android

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import java.io.File

/** Application entry: notification channel + the node's data directory. */
class KommsApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ThemeController.initialize(this)
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                NodeService.CHANNEL_ID,
                getString(R.string.notif_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    companion object {
        /** The node's data directory (encrypted store + settings.json). */
        fun dataDir(app: Application): File = File(app.filesDir, "node")
    }
}
