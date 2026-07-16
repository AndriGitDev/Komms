package komms.android

import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity

/**
 * Always-on B14 boundary for every Komms activity, including the locked gate.
 * The flag is installed before AppCompat restores or draws any content, so
 * screenshots, screen recording, and Android recent-task previews are blocked.
 */
abstract class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }
}
