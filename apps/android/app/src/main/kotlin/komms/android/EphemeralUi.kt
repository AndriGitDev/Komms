package komms.android

import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

internal val EPHEMERAL_LIFETIMES = listOf<ULong?>(null, 60uL, 3_600uL, 86_400uL, 604_800uL, 2_592_000uL)
internal val VIEW_ONCE_LIFETIMES = listOf(3_600uL, 86_400uL, 604_800uL, 2_592_000uL)

internal fun AppCompatActivity.configureEphemeralComposer(onEnabled: (() -> Unit)? = null) {
    val spinner = findViewById<Spinner>(R.id.chat_ephemeral_lifetime)
    val honesty = findViewById<TextView>(R.id.chat_ephemeral_honesty)
    val chip = findViewById<TextView>(R.id.chat_ephemeral_chip)
    val section = findViewById<View>(R.id.chat_ephemeral_section)
    val labels = listOf(
        getString(R.string.ephemeral_off), getString(R.string.ephemeral_one_minute),
        getString(R.string.ephemeral_one_hour), getString(R.string.ephemeral_one_day),
        getString(R.string.ephemeral_seven_days), getString(R.string.ephemeral_thirty_days),
    )
    spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)
    // The picker row lives in the "+" menu; while it is tucked away, an
    // active lifetime stays visible as a chip that re-opens the row.
    chip.setOnClickListener { section.visibility = View.VISIBLE }
    spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
        override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
            honesty.visibility = if (position == 0) View.GONE else View.VISIBLE
            chip.visibility = if (position == 0) View.GONE else View.VISIBLE
            if (position != 0) {
                chip.text = getString(
                    R.string.ephemeral_chip_active,
                    labels[position],
                )
            }
            if (position != 0) onEnabled?.invoke()
        }
        override fun onNothingSelected(parent: AdapterView<*>?) = Unit
    }
}

internal fun AppCompatActivity.selectedEphemeralLifetime(): ULong? =
    EPHEMERAL_LIFETIMES[findViewById<Spinner>(R.id.chat_ephemeral_lifetime).selectedItemPosition]

internal fun lifetimeLabels(activity: AppCompatActivity): List<String> = listOf(
    activity.getString(R.string.ephemeral_one_hour),
    activity.getString(R.string.ephemeral_one_day),
    activity.getString(R.string.ephemeral_seven_days),
    activity.getString(R.string.ephemeral_thirty_days),
)
