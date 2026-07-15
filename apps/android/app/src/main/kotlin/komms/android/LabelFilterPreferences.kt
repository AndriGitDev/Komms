package komms.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Process-restart label-filter restoration without putting label ids or mode
 * into ordinary saved state, logs, previews, or plaintext SharedPreferences.
 */
internal class LabelFilterPreferences(private val context: Context) {
    data class State(val ids: List<String>, val mode: String)

    private val preferences by lazy {
        context.getSharedPreferences("protected_label_filter", Context.MODE_PRIVATE)
    }

    fun load(): State = runCatching {
        val iv = Base64.decode(preferences.getString("iv", null) ?: return State(emptyList(), "any"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(preferences.getString("ciphertext", null) ?: return State(emptyList(), "any"), Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        val fields = String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8).split('\n')
        val mode = fields.firstOrNull().takeIf { it == "any" || it == "all" } ?: "any"
        State(fields.drop(1).filter { it.matches(Regex("[0-9a-f]{32}")) }.distinct(), mode)
    }.getOrElse {
        preferences.edit().clear().apply()
        State(emptyList(), "any")
    }

    fun save(state: State) {
        val safeMode = if (state.mode == "all") "all" else "any"
        val ids = state.ids.filter { it.matches(Regex("[0-9a-f]{32}")) }.distinct().take(128)
        val plaintext = (listOf(safeMode) + ids).joinToString("\n").toByteArray(StandardCharsets.UTF_8)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ciphertext = cipher.doFinal(plaintext)
        preferences.edit()
            .putString("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .apply()
        plaintext.fill(0)
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "komms-private-label-filter-v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
