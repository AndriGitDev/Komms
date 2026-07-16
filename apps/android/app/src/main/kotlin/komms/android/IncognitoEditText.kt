package komms.android

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.appcompat.widget.AppCompatEditText

/**
 * B15 text editor used by every Komms activity and dialog.
 *
 * Android explicitly documents the no-personalized-learning flag as a request
 * that an IME may ignore. Applying it both to the view and the final
 * [EditorInfo] keeps XML and programmatic fields covered without overstating
 * what a third-party keyboard guarantees.
 */
class IncognitoEditText @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = android.R.attr.editTextStyle,
) : AppCompatEditText(context, attrs, defStyleAttr) {
    init {
        imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
    }

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        val connection = super.onCreateInputConnection(outAttrs)
        outAttrs.imeOptions =
            outAttrs.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        if (outAttrs.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT) {
            outAttrs.inputType =
                outAttrs.inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        return connection
    }
}
