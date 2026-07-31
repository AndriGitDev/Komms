package komms.android

import android.content.Context
import komms.core.NativeWakePreference

/** Secret-free local preference; native provider tokens never enter it. */
class NativeWakePreferences(context: Context) {
    private val preferences =
        context.getSharedPreferences("komms.native-wake", Context.MODE_PRIVATE)

    fun load(): NativeWakePreference = when (preferences.getString(PROFILE, DISABLED)) {
        BACKGROUND -> NativeWakePreference.BACKGROUND_ONLY
        VISIBLE -> NativeWakePreference.GENERIC_VISIBLE
        else -> NativeWakePreference.DISABLED
    }

    fun save(preference: NativeWakePreference) {
        val value = when (preference) {
            NativeWakePreference.DISABLED -> DISABLED
            NativeWakePreference.BACKGROUND_ONLY -> BACKGROUND
            NativeWakePreference.GENERIC_VISIBLE -> VISIBLE
        }
        preferences.edit().putString(PROFILE, value).apply()
    }

    companion object {
        private const val PROFILE = "profile"
        private const val DISABLED = "disabled"
        private const val BACKGROUND = "background"
        private const val VISIBLE = "visible"
    }
}
