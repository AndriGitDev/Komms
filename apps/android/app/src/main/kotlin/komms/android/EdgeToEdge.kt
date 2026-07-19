package komms.android

import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/// Android 15 enforces edge-to-edge for targetSdk 35: without this, every
/// screen draws under the status bar and behind the gesture/IME area. Pads
/// the window's content frame by the system-bar and display-cutout insets,
/// and by the keyboard when it is taller — which is also what makes the
/// composer rise with the IME (together with adjustResize in the manifest).
internal fun AppCompatActivity.applyEdgeToEdgeInsets() {
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
        val bars = insets.getInsets(
            WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
        )
        val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
        view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
        WindowInsetsCompat.CONSUMED
    }
}
