package komms.android

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import komms.core.Session
import uniffi.kult_ffi.Attachment
import uniffi.kult_ffi.AttachmentState
import uniffi.kult_ffi.AudioInfo

private const val AUDIO_RATE = 16_000
private const val AUDIO_MAX_SAMPLES = AUDIO_RATE * 60
private const val AUDIO_MIME = "audio/wav"

/** Foreground-only recorder/reviewer plus protected attachment playback. */
class AudioMessageController(
    private val activity: AppCompatActivity,
    private val send: (Session, File) -> String,
    private val carrierExplanation: (Session) -> String,
    private val refresh: () -> Unit,
) {
    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "komms-audio-recording").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())
    private val audioManager = activity.getSystemService(AudioManager::class.java)
    private val focusListener = AudioManager.OnAudioFocusChangeListener { change ->
        if (change == AudioManager.AUDIOFOCUS_LOSS ||
            change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT ||
            change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK
        ) {
            main.post {
                if (recorder != null) {
                    discardCapture(activity.getString(R.string.audio_interrupted_discarded))
                }
                releasePlayer()
            }
        }
    }
    private val capturing = AtomicBoolean(false)
    private var recorder: AudioRecord? = null
    private var rawFile: File? = null
    private var sampleCount = 0
    private var finishing = false
    private var reviewFile: File? = null
    private var reviewDialog: AlertDialog? = null
    private var player: MediaPlayer? = null
    private var playerFile: File? = null
    private var playerSeek: SeekBar? = null
    private var progressTask: Runnable? = null
    private val recordButton: Button = activity.findViewById(R.id.chat_record)
    private val recordStatus: TextView = activity.findViewById(R.id.chat_recording_status)

    private val permission = activity.registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) startCapture() else explainPermissionDenial()
    }

    init {
        cleanupOrphans()
        recordButton.setOnClickListener {
            if (recorder == null) requestRecording() else stopCapture(review = true)
        }
    }

    private fun cleanupOrphans() {
        activity.cacheDir.listFiles()?.filter {
            it.name.startsWith("audio-recording-") || it.name.startsWith("audio-playback-")
        }?.forEach(File::delete)
    }

    private fun requestRecording() {
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startCapture()
        } else {
            permission.launch(Manifest.permission.RECORD_AUDIO)
        }
    }

    private fun explainPermissionDenial() {
        recordStatus.text = activity.getString(R.string.audio_permission_denied)
        if (!activity.shouldShowRequestPermissionRationale(Manifest.permission.RECORD_AUDIO)) {
            AlertDialog.Builder(activity)
                .setTitle(R.string.audio_permission_title)
                .setMessage(R.string.audio_permission_settings)
                .setPositiveButton(R.string.audio_open_settings) { _, _ ->
                    activity.startActivity(
                        Intent(
                            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:${activity.packageName}"),
                        ),
                    )
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun startCapture() {
        discardReview()
        val minimum = AudioRecord.getMinBufferSize(
            AUDIO_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        )
        if (minimum <= 0) return activity.toast(activity.getString(R.string.audio_record_failed))
        val focus = audioManager.requestAudioFocus(
            focusListener,
            AudioManager.STREAM_MUSIC,
            AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE,
        )
        if (focus != AudioManager.AUDIOFOCUS_REQUEST_GRANTED) {
            return activity.toast(activity.getString(R.string.audio_focus_failed))
        }
        val audio = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            AUDIO_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            minimum * 2,
        )
        if (audio.state != AudioRecord.STATE_INITIALIZED) {
            audio.release()
            audioManager.abandonAudioFocus(focusListener)
            return activity.toast(activity.getString(R.string.audio_record_failed))
        }
        val file = File(activity.cacheDir, "audio-recording-${UUID.randomUUID()}.native.wav")
        rawFile = file
        recorder = audio
        sampleCount = 0
        finishing = false
        capturing.set(true)
        try {
            audio.startRecording()
        } catch (error: Exception) {
            capturing.set(false)
            recorder = null
            rawFile = null
            file.delete()
            audio.release()
            audioManager.abandonAudioFocus(focusListener)
            return activity.toast(activity.getString(R.string.audio_record_failed))
        }
        recordButton.setText(R.string.audio_stop)
        recordButton.contentDescription = activity.getString(R.string.audio_stop_description)
        recordStatus.text = activity.getString(R.string.audio_recording)
        worker.execute { recordLoop(audio, file, minimum) }
    }

    private fun recordLoop(audio: AudioRecord, file: File, minimum: Int) {
        try {
            FileOutputStream(file).use { output ->
                output.write(ByteArray(44))
                val samples = ShortArray(minimum.coerceAtLeast(1024))
                while (capturing.get() && sampleCount < AUDIO_MAX_SAMPLES) {
                    val read = audio.read(samples, 0, minOf(samples.size, AUDIO_MAX_SAMPLES - sampleCount))
                    if (read < 0) {
                        if (!capturing.get()) break
                        throw IllegalStateException("AudioRecord read failed: $read")
                    }
                    val bytes = ByteArray(read * 2)
                    for (index in 0 until read) {
                        val value = samples[index].toInt()
                        bytes[index * 2] = value.toByte()
                        bytes[index * 2 + 1] = (value ushr 8).toByte()
                    }
                    output.write(bytes)
                    sampleCount += read
                }
                output.fd.sync()
            }
            if (sampleCount >= AUDIO_MAX_SAMPLES) {
                main.post {
                    recordStatus.text = activity.getString(R.string.audio_limit_reached)
                    stopCapture(review = true)
                }
            }
        } catch (error: Exception) {
            main.post { discardCapture(activity.getString(R.string.audio_record_failed)) }
        }
    }

    private fun stopCapture(review: Boolean) {
        val audio = recorder ?: return
        if (finishing) return
        finishing = true
        capturing.set(false)
        try { audio.stop() } catch (_: IllegalStateException) {}
        audio.release()
        recorder = null
        audioManager.abandonAudioFocus(focusListener)
        recordButton.setText(R.string.audio_record)
        recordButton.contentDescription = activity.getString(R.string.audio_record_description)
        val source = rawFile
        rawFile = null
        worker.execute {
            if (source == null || !review || sampleCount == 0) {
                source?.delete()
                main.post { recordStatus.text = activity.getString(R.string.audio_discarded) }
                return@execute
            }
            try {
                writeHeader(source, sampleCount)
                val canonical = File(
                    activity.cacheDir,
                    "audio-recording-${UUID.randomUUID()}.wav",
                )
                val session = NodeHolder.session ?: throw IllegalStateException("locked")
                val info = session.canonicalizeAudio(source, canonical)
                source.delete()
                main.post {
                    if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                        showReview(canonical, info)
                    } else {
                        canonical.delete()
                    }
                }
            } catch (error: Exception) {
                source.delete()
                main.post {
                    recordStatus.text = error.message ?: activity.getString(R.string.audio_record_failed)
                    activity.toast(recordStatus.text.toString())
                }
            }
        }
    }

    private fun writeHeader(file: File, samples: Int) {
        val dataLength = samples * 2
        RandomAccessFile(file, "rw").use { output ->
            fun ascii(value: String) = output.write(value.toByteArray(Charsets.US_ASCII))
            fun u16(value: Int) {
                output.write(value and 0xff)
                output.write(value ushr 8 and 0xff)
            }
            fun u32(value: Int) {
                u16(value and 0xffff)
                u16(value ushr 16 and 0xffff)
            }
            ascii("RIFF"); u32(36 + dataLength); ascii("WAVEfmt "); u32(16)
            u16(1); u16(1); u32(AUDIO_RATE); u32(AUDIO_RATE * 2); u16(2); u16(16)
            ascii("data"); u32(dataLength)
            output.fd.sync()
        }
    }

    private fun showReview(file: File, info: AudioInfo) {
        reviewFile = file
        recordStatus.text = activity.getString(R.string.audio_review_ready)
        val root = activity.layoutInflater.inflate(R.layout.dialog_audio_review, null)
        root.findViewById<TextView>(R.id.audio_review_duration).text = duration(info.durationMs)
        root.findViewById<AudioWaveformView>(R.id.audio_review_waveform).submit(info.waveform)
        val play = root.findViewById<Button>(R.id.audio_review_play)
        val seek = root.findViewById<SeekBar>(R.id.audio_review_seek)
        play.setOnClickListener { togglePlayback(file, play, seek) }
        val session = NodeHolder.session
        val carrierView = root.findViewById<TextView>(R.id.audio_review_carrier)
        carrierView.text = try {
            if (session == null) activity.getString(R.string.audio_locked)
            else carrierExplanation(session)
        } catch (error: Exception) {
            error.message
        }
        val dialog = AlertDialog.Builder(activity)
            .setTitle(R.string.audio_review_title)
            .setView(root)
            .setNegativeButton(R.string.audio_discard) { _, _ -> discardReview() }
            .setPositiveButton(R.string.audio_send, null)
            .setOnCancelListener { discardReview() }
            .create()
        reviewDialog = dialog
        dialog.setOnDismissListener { reviewDialog = null }
        dialog.setOnShowListener {
            val sendButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            sendButton.setOnClickListener {
                val active = NodeHolder.session ?: return@setOnClickListener
                val latestCarrier = try {
                    carrierExplanation(active)
                } catch (error: Exception) {
                    activity.toast(error.message ?: activity.getString(R.string.audio_record_failed))
                    return@setOnClickListener
                }
                if (latestCarrier != carrierView.text.toString()) {
                    carrierView.text = latestCarrier
                    activity.toast(activity.getString(R.string.audio_carrier_changed))
                    return@setOnClickListener
                }
                sendButton.isEnabled = false
                releasePlayer()
                reviewFile = null
                runNode(
                    work = { send(active, file) },
                    onError = {
                        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                            reviewFile = file
                            sendButton.isEnabled = true
                            activity.toast(it)
                        } else {
                            file.delete()
                        }
                    },
                ) {
                    file.delete()
                    reviewDialog = null
                    dialog.dismiss()
                    refresh()
                }
            }
        }
        dialog.show()
    }

    private fun togglePlayback(file: File, button: Button, seek: SeekBar) {
        val current = player
        if (current != null) {
            if (current.isPlaying) {
                current.pause(); button.setText(R.string.audio_play)
            } else {
                current.start(); button.setText(R.string.audio_pause); scheduleProgress()
            }
            return
        }
        requestPlaybackFocus()
        playerSeek = seek
        player = MediaPlayer().apply {
            setAudioAttributes(
                AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build(),
            )
            setDataSource(file.absolutePath)
            setOnPreparedListener {
                seek.max = duration
                seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(bar: SeekBar, value: Int, fromUser: Boolean) {
                        if (fromUser) seekTo(value)
                    }
                    override fun onStartTrackingTouch(bar: SeekBar) = Unit
                    override fun onStopTrackingTouch(bar: SeekBar) = Unit
                })
                start(); button.setText(R.string.audio_pause); scheduleProgress()
            }
            setOnCompletionListener { button.setText(R.string.audio_play); seek.progress = 0 }
            prepareAsync()
        }
    }

    private fun requestPlaybackFocus() {
        audioManager.requestAudioFocus(
            focusListener,
            AudioManager.STREAM_MUSIC,
            AudioManager.AUDIOFOCUS_GAIN_TRANSIENT,
        )
    }

    private fun scheduleProgress() {
        progressTask?.let(main::removeCallbacks)
        progressTask = object : Runnable {
            override fun run() {
                val active = player ?: return
                playerSeek?.progress = active.currentPosition
                if (active.isPlaying) main.postDelayed(this, 250)
            }
        }.also { main.post(it) }
    }

    fun bindAttachment(attachment: Attachment, container: LinearLayout) {
        val primary = attachment.objects.firstOrNull { !it.preview }
        val available = primary?.mediaType == AUDIO_MIME && attachment.state == AttachmentState.COMPLETE
        container.visibility = if (available) View.VISIBLE else View.GONE
        if (!available) return
        container.tag = attachment.transferId
        val waveform = container.findViewById<AudioWaveformView>(R.id.attachment_audio_waveform)
        val durationView = container.findViewById<TextView>(R.id.attachment_audio_duration)
        val play = container.findViewById<Button>(R.id.attachment_audio_play)
        val seek = container.findViewById<SeekBar>(R.id.attachment_audio_seek)
        play.setOnClickListener { playAttachment(attachment.transferId, play, seek) }
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                val file = File(activity.cacheDir, "audio-playback-${UUID.randomUUID()}.wav")
                try {
                    session.exportAttachment(attachment.transferId, file)
                    session.probeAudio(file)
                } finally {
                    file.delete()
                }
            },
            onError = {},
        ) { info ->
            if (container.tag == attachment.transferId) {
                waveform.submit(info.waveform)
                durationView.text = duration(info.durationMs)
            }
        }
    }

    private fun playAttachment(transfer: String, button: Button, seek: SeekBar) {
        releasePlayer()
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                File(activity.cacheDir, "audio-playback-${UUID.randomUUID()}.wav").also {
                    session.exportAttachment(transfer, it)
                    session.probeAudio(it)
                }
            },
            onError = { activity.toast(it) },
        ) { file ->
            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                playerFile = file
                togglePlayback(file, button, seek)
            } else {
                file.delete()
            }
        }
    }

    private fun duration(milliseconds: ULong): String {
        val seconds = milliseconds.toLong() / 1000
        return "%d:%02d · mono PCM WAV · 16 kHz".format(seconds / 60, seconds % 60)
    }

    private fun discardCapture(reason: String) {
        capturing.set(false)
        try { recorder?.stop() } catch (_: IllegalStateException) {}
        recorder?.release()
        recorder = null
        rawFile?.delete()
        rawFile = null
        audioManager.abandonAudioFocus(focusListener)
        recordButton.setText(R.string.audio_record)
        recordStatus.text = reason
    }

    private fun discardReview() {
        releasePlayer()
        reviewFile?.delete()
        reviewFile = null
        recordStatus.text = activity.getString(R.string.audio_discarded)
    }

    private fun releasePlayer() {
        progressTask?.let(main::removeCallbacks)
        progressTask = null
        player?.release()
        player = null
        playerSeek = null
        playerFile?.delete()
        playerFile = null
        audioManager.abandonAudioFocus(focusListener)
    }

    fun onStop() {
        if (recorder != null) discardCapture(activity.getString(R.string.audio_interrupted_discarded))
        reviewDialog?.dismiss()
        reviewDialog = null
        if (reviewFile != null) discardReview()
        releasePlayer()
    }

    fun close() {
        onStop()
        discardReview()
        worker.shutdownNow()
    }
}
