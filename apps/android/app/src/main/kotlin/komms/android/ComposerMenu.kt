package komms.android

import android.view.View
import android.widget.ImageButton
import android.widget.PopupMenu
import androidx.appcompat.app.AppCompatActivity

/// The "+" composer menu: secondary actions live here so the text field
/// keeps the row's width. Menu items delegate to the hidden action buttons
/// (`chat_hidden_actions`), whose visibility still carries availability —
/// groups enable mention/poll on those buttons exactly as before — so the
/// activities' and controllers' click wiring is untouched.
internal fun AppCompatActivity.configureComposerMenu() {
    val more = findViewById<ImageButton>(R.id.chat_more)
    more.setOnClickListener {
        val schedule = findViewById<View>(R.id.chat_schedule)
        val mention = findViewById<View>(R.id.chat_mention)
        val poll = findViewById<View>(R.id.chat_poll)
        val ephemeral = findViewById<View>(R.id.chat_ephemeral_section)
        val menu = PopupMenu(this, more)
        var next = 1
        val actions = mutableMapOf<Int, () -> Unit>()
        fun add(title: String, run: () -> Unit) {
            menu.menu.add(0, next, next, title)
            actions[next] = run
            next += 1
        }
        add(getString(R.string.chat_schedule)) { schedule.performClick() }
        if (mention.visibility == View.VISIBLE) {
            add(getString(R.string.mention_member)) { mention.performClick() }
        }
        if (poll.visibility == View.VISIBLE) {
            add(getString(R.string.poll_create_action)) { poll.performClick() }
        }
        add(getString(R.string.ephemeral_remove_after)) {
            ephemeral.visibility =
                if (ephemeral.visibility == View.VISIBLE) View.GONE else View.VISIBLE
        }
        menu.setOnMenuItemClickListener { item ->
            actions[item.itemId]?.invoke()
            true
        }
        menu.show()
    }
}
