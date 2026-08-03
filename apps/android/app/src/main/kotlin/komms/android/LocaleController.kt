package komms.android

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

/**
 * Applies the private shell-language preference without changing any account,
 * protocol, trust, or delivery state.
 */
object LocaleController {
    const val SYSTEM = "system"
    const val ENGLISH = "en-US"
    const val ICELANDIC = "is"

    private const val STORE = "appearance"
    private const val KEY = "locale"
    private lateinit var appContext: Context

    fun initialize(context: Context) {
        appContext = context.applicationContext
        apply(cached())
    }

    fun cached(): String =
        appContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)
            .getString(KEY, SYSTEM)
            .takeIf { it in setOf(SYSTEM, ENGLISH, ICELANDIC) }
            ?: SYSTEM

    fun select(preference: String) {
        require(preference in setOf(SYSTEM, ENGLISH, ICELANDIC))
        if (preference == cached()) return
        appContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY, preference)
            .apply()
        apply(preference)
    }

    fun preferenceFor(checkedId: Int): String = when (checkedId) {
        R.id.set_language_english -> ENGLISH
        R.id.set_language_icelandic -> ICELANDIC
        else -> SYSTEM
    }

    fun checkedId(): Int = when (cached()) {
        ENGLISH -> R.id.set_language_english
        ICELANDIC -> R.id.set_language_icelandic
        else -> R.id.set_language_system
    }

    private fun apply(preference: String) {
        val locales = if (preference == SYSTEM) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(preference)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }
}
