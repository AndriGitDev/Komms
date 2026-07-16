package komms.android

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatDelegate
import komms.core.Session
import uniffi.kult_ffi.ThemePreference

/**
 * Applies B12 before the first Activity is created and reconciles the small,
 * non-sensitive pre-unlock cache with the authoritative sealed F5 record.
 */
object ThemeController {
    private const val STORE = "appearance"
    private const val KEY = "theme"
    private lateinit var appContext: Context

    fun initialize(context: Context) {
        appContext = context.applicationContext
        apply(cached())
    }

    fun cached(): ThemePreference {
        val value = appContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)
            .getString(KEY, "system")
        return when (value) {
            "light" -> ThemePreference.LIGHT
            "dark" -> ThemePreference.DARK
            else -> ThemePreference.SYSTEM
        }
    }

    /** Apply immediately, cache for the next gate, and optionally seal. */
    fun select(preference: ThemePreference, session: Session? = NodeHolder.session) {
        cache(preference)
        apply(preference)
        session?.let { NodeHolder.executor.execute { it.setTheme(preference) } }
    }

    /** Run off the UI thread after unlock/restore, before navigation. */
    fun reconcile(session: Session) {
        val info = session.theme()
        val authoritative = if (info.persisted) {
            info.preference
        } else {
            cached().also { session.setTheme(it) }
        }
        cache(authoritative)
        Handler(Looper.getMainLooper()).post { apply(authoritative) }
    }

    private fun cache(preference: ThemePreference) {
        appContext.getSharedPreferences(STORE, Context.MODE_PRIVATE).edit()
            .putString(KEY, preference.token()).apply()
    }

    private fun apply(preference: ThemePreference) {
        AppCompatDelegate.setDefaultNightMode(
            when (preference) {
                ThemePreference.SYSTEM -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                ThemePreference.LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
                ThemePreference.DARK -> AppCompatDelegate.MODE_NIGHT_YES
            },
        )
    }
}

fun ThemePreference.token(): String = when (this) {
    ThemePreference.SYSTEM -> "system"
    ThemePreference.LIGHT -> "light"
    ThemePreference.DARK -> "dark"
}
