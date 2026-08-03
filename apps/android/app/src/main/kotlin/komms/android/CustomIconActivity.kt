package komms.android

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import java.io.File
import uniffi.kult_ffi.CustomIcon
import uniffi.kult_ffi.CustomIconTarget
import uniffi.kult_ffi.CustomIconTargetKind

/** Local-only custom-icon display and management for every B13 target type. */
class CustomIconActivity : SecureActivity() {
    private data class Choice(val target: CustomIconTarget, val label: String) {
        override fun toString(): String = label
    }

    private var choices = listOf<Choice>()

    private val openImage = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@registerForActivityResult
        val choice = selected() ?: return@registerForActivityResult
        val session = NodeHolder.session ?: return@registerForActivityResult
        runNode(work = {
            val local = File.createTempFile("private-icon-", ".image", cacheDir)
            try {
                contentResolver.openInputStream(uri).use { input ->
                    requireNotNull(input) { "selected image is unavailable" }
                    local.outputStream().use(input::copyTo)
                }
                session.setCustomIconFromPath(choice.target, local)
            } finally {
                local.delete()
            }
        }) { icon ->
            render(choice, icon)
            toast(getString(R.string.icons_saved))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        setContentView(R.layout.activity_custom_icons)
        applyEdgeToEdgeInsets()
        setSupportActionBar(findViewById(R.id.icons_toolbar))
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.icons_title)

        val glyphRoot = findViewById<LinearLayout>(R.id.icons_glyphs)
        listOf("person", "group", "folder", "note", "star", "heart", "shield", "compass")
            .chunked(4)
            .forEach { glyphs ->
                glyphRoot.addView(LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    glyphs.forEach { glyph ->
                        addView(Button(this@CustomIconActivity).apply {
                            val label = glyphLabel(glyph)
                            text = label
                            contentDescription = getString(
                                R.string.icons_use_bundled_glyph,
                                label,
                            )
                            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                            setOnClickListener { setGlyph(glyph) }
                        })
                    }
                })
            }
        findViewById<View>(R.id.icons_choose_image).setOnClickListener {
            openImage.launch(arrayOf("image/jpeg", "image/png"))
        }
        findViewById<View>(R.id.icons_clear).setOnClickListener { clearIcon() }
        loadTargets()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun loadTargets() {
        val session = NodeHolder.session ?: return
        runNode(work = {
            listOf(Choice(CustomIconTarget(CustomIconTargetKind.NOTE_TO_SELF, null), getString(R.string.note_to_self_title))) +
                session.contacts().map {
                    Choice(
                        CustomIconTarget(CustomIconTargetKind.CONTACT, it.peer),
                        getString(R.string.icons_contact_target, it.name),
                    )
                } +
                session.groups().map {
                    Choice(
                        CustomIconTarget(CustomIconTargetKind.GROUP, it.id),
                        getString(R.string.icons_group_target, it.name),
                    )
                } +
                session.folders().map {
                    Choice(
                        CustomIconTarget(CustomIconTargetKind.FOLDER, it.id),
                        getString(
                            R.string.icons_folder_target,
                            (it.order + 1u).toLong(),
                            it.name,
                        ),
                    )
                }
        }) { loaded ->
            choices = loaded
            findViewById<Spinner>(R.id.icons_target).apply {
                adapter = ArrayAdapter(this@CustomIconActivity, android.R.layout.simple_spinner_dropdown_item, choices)
                onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) = refresh()
                    override fun onNothingSelected(parent: AdapterView<*>?) = Unit
                }
            }
        }
    }

    private fun selected(): Choice? =
        choices.getOrNull(findViewById<Spinner>(R.id.icons_target).selectedItemPosition)

    private fun refresh() {
        val choice = selected() ?: return
        val session = NodeHolder.session ?: return
        runNode(work = { session.customIcon(choice.target) to session.customIconUsage() }) { (icon, usage) ->
            render(choice, icon)
            findViewById<TextView>(R.id.icons_usage).text = getString(
                R.string.icons_usage,
                usage.records.toLong(),
                usage.bytes.toLong(),
            )
        }
    }

    private fun render(choice: Choice, icon: CustomIcon?) {
        findViewById<ImageView>(R.id.icons_preview).setImageDrawable(
            customIconDrawable(this, icon, choice.label, 96),
        )
        findViewById<View>(R.id.icons_clear).isEnabled = icon != null
        val session = NodeHolder.session ?: return
        runNode(work = { session.customIconUsage() }) { usage ->
            findViewById<TextView>(R.id.icons_usage).text = getString(
                R.string.icons_usage,
                usage.records.toLong(),
                usage.bytes.toLong(),
            )
        }
    }

    private fun setGlyph(glyph: String) {
        val choice = selected() ?: return
        val session = NodeHolder.session ?: return
        runNode(work = { session.setBundledCustomIcon(choice.target, glyph) }) { icon ->
            render(choice, icon)
            toast(getString(R.string.icons_saved))
        }
    }

    private fun glyphLabel(glyph: String): String = getString(
        when (glyph) {
            "person" -> R.string.icon_glyph_person
            "group" -> R.string.icon_glyph_group
            "folder" -> R.string.icon_glyph_folder
            "note" -> R.string.icon_glyph_note
            "star" -> R.string.icon_glyph_star
            "heart" -> R.string.icon_glyph_heart
            "shield" -> R.string.icon_glyph_shield
            "compass" -> R.string.icon_glyph_compass
            else -> R.string.icon_glyph_unknown
        },
    )

    private fun clearIcon() {
        val choice = selected() ?: return
        val session = NodeHolder.session ?: return
        runNode(work = { session.clearCustomIcon(choice.target) }) {
            render(choice, null)
            toast(getString(R.string.icons_cleared))
        }
    }
}
