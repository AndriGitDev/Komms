package komms.android

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioFocusRequest
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import android.media.MediaRecorder
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.TextView
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import komms.core.Session
import uniffi.kult_ffi.Call
import uniffi.kult_ffi.CallDirection
import uniffi.kult_ffi.CallEndReason
import uniffi.kult_ffi.CallPhase
import uniffi.kult_ffi.CallUnavailableReason

/**
 * Foreground-only Android live-call adapter. The shared core owns signaling,
 * authentication, encryption, bounds, and jitter; this class only converts
 * 48 kHz mono PCM to/from native MediaCodec Opus packets.
 */
class CallController(
    private val activity: ChatActivity,
    private val peer: String,
    private val contactName: String,
    private val withMicrophonePermission: (() -> Unit) -> Unit,
) {
    private val button = activity.findViewById<Button>(R.id.chat_call)
    private val status = activity.findViewById<TextView>(R.id.chat_call_status)
    private val audioManager = activity.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private val main = Handler(Looper.getMainLooper())
    private val focusListener = AudioManager.OnAudioFocusChangeListener { change ->
        if (change == AudioManager.AUDIOFOCUS_LOSS) {
            main.post {
                val snapshot = call
                stopMedia()
                if (!closed && snapshot != null && snapshot.phase != CallPhase.ENDED) {
                    runNode { it.hangupCall(snapshot.id) }
                }
            }
        }
    }
    private val focusRequest = AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
        .setAudioAttributes(
            AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                .build(),
        )
        .setOnAudioFocusChangeListener(focusListener)
        .build()
    private var call: Call? = null
    private var media: ActiveMedia? = null
    private var incomingPrompt: String? = null
    private var incomingDialog: AlertDialog? = null
    private var closed = false

    init {
        button.setOnClickListener { onButton() }
        refresh()
    }

    fun onResume() = refresh()

    fun onCallUpdated(snapshot: Call) {
        if (snapshot.peer != peer) return
        call = snapshot
        when (snapshot.phase) {
            CallPhase.RINGING -> {
                showStatus(
                    activity.getString(
                        if (snapshot.direction == CallDirection.INCOMING) {
                            R.string.call_incoming
                        } else {
                            R.string.call_ringing
                        },
                    ),
                )
                if (snapshot.direction == CallDirection.INCOMING && incomingPrompt != snapshot.id) {
                    incomingPrompt = snapshot.id
                    promptIncoming(snapshot)
                }
            }
            CallPhase.CONNECTING -> showStatus(activity.getString(R.string.call_connecting))
            CallPhase.ACTIVE -> {
                showStatus(activity.getString(R.string.call_active))
                startMedia(snapshot.id)
            }
            CallPhase.ENDED -> {
                incomingDialog?.dismiss()
                incomingDialog = null
                stopMedia()
                showStatus(endText(snapshot.endReason))
            }
        }
        renderButton()
    }

    /** Foreground-only contract: leaving the activity ends capture and call. */
    fun onStop() {
        val snapshot = call
        incomingDialog?.dismiss()
        incomingDialog = null
        stopMedia()
        if (snapshot != null && snapshot.phase != CallPhase.ENDED) {
            NodeHolder.executor.execute {
                runCatching {
                    val session = NodeHolder.session ?: return@runCatching
                    if (snapshot.phase == CallPhase.RINGING) {
                        if (snapshot.direction == CallDirection.OUTGOING) {
                            session.cancelCall(snapshot.id)
                        } else {
                            session.declineCall(snapshot.id)
                        }
                    } else {
                        session.hangupCall(snapshot.id)
                    }
                }
            }
        }
    }

    fun close() {
        closed = true
        onStop()
    }

    private fun onButton() {
        val snapshot = call?.takeIf { it.phase != CallPhase.ENDED }
        when {
            snapshot?.phase == CallPhase.RINGING && snapshot.direction == CallDirection.OUTGOING ->
                runNode { it.cancelCall(snapshot.id) }
            snapshot?.phase == CallPhase.RINGING && snapshot.direction == CallDirection.INCOMING ->
                runNode { it.declineCall(snapshot.id) }
            snapshot != null -> {
                stopMedia()
                runNode { it.hangupCall(snapshot.id) }
            }
            else -> withMicrophonePermission {
                runNode(
                    action = { it.startCall(peer) },
                    success = { session, id ->
                        showStatus(activity.getString(R.string.call_ringing))
                        call = session.calls().firstOrNull { row -> row.id == id }
                        renderButton()
                    },
                )
            }
        }
    }

    private fun promptIncoming(snapshot: Call) {
        incomingDialog = AlertDialog.Builder(activity)
            .setTitle(activity.getString(R.string.call_incoming_title, contactName))
            .setMessage(R.string.call_direct_quic_note)
            .setPositiveButton(R.string.call_answer) { _, _ ->
                withMicrophonePermission { runNode { it.answerCall(snapshot.id) } }
            }
            .setNegativeButton(R.string.call_decline) { _, _ ->
                runNode { it.declineCall(snapshot.id) }
            }
            .setOnCancelListener { runNode { it.declineCall(snapshot.id) } }
            .show()
    }

    private fun refresh() {
        NodeHolder.executor.execute {
            val session = NodeHolder.session ?: return@execute
            val active = runCatching {
                session.calls().firstOrNull { it.peer == peer && it.phase != CallPhase.ENDED }
            }.getOrNull()
            val result = if (active == null) {
                runCatching { session.callAvailability(peer) }.getOrNull()
            } else {
                null
            }
            activity.runOnUiThread {
                if (closed) return@runOnUiThread
                if (active != null) {
                    onCallUpdated(active)
                    return@runOnUiThread
                }
                if (call?.phase?.let { it != CallPhase.ENDED } == true) return@runOnUiThread
                button.isEnabled = result?.available == true
                button.contentDescription = if (result?.available == true) {
                    activity.getString(R.string.call_start_description)
                } else {
                    unavailableText(result?.unavailable)
                }
                if (result?.available != true) showStatus(unavailableText(result?.unavailable))
            }
        }
    }

    private fun renderButton() {
        val snapshot = call?.takeIf { it.phase != CallPhase.ENDED }
        button.isEnabled = true
        button.text = when {
            snapshot?.phase == CallPhase.RINGING && snapshot.direction == CallDirection.OUTGOING ->
                activity.getString(R.string.call_cancel)
            snapshot?.phase == CallPhase.RINGING && snapshot.direction == CallDirection.INCOMING ->
                activity.getString(R.string.call_decline)
            snapshot != null -> activity.getString(R.string.call_hangup)
            else -> activity.getString(R.string.call_start)
        }
        button.contentDescription = button.text
        if (snapshot == null) refresh()
    }

    private fun showStatus(text: String) {
        status.text = text
        status.visibility = if (text.isBlank()) View.GONE else View.VISIBLE
    }

    private fun unavailableText(reason: CallUnavailableReason?): String = when (reason) {
        CallUnavailableReason.OFFLINE_OR_UNKNOWN -> activity.getString(R.string.call_offline)
        CallUnavailableReason.BULK_ONLY -> activity.getString(R.string.call_bulk_only)
        CallUnavailableReason.MESH_ONLY -> activity.getString(R.string.call_mesh_only)
        CallUnavailableReason.MISSING_SESSION -> activity.getString(R.string.call_missing_session)
        CallUnavailableReason.UNSUPPORTED -> activity.getString(R.string.call_unsupported)
        CallUnavailableReason.ALREADY_IN_CALL -> activity.getString(R.string.call_already_active)
        null -> activity.getString(R.string.call_unavailable)
    }

    private fun endText(reason: CallEndReason?): String = when (reason) {
        CallEndReason.DECLINED -> activity.getString(R.string.call_declined)
        CallEndReason.BUSY -> activity.getString(R.string.call_busy)
        CallEndReason.CANCELLED -> activity.getString(R.string.call_cancelled)
        CallEndReason.HUNG_UP -> activity.getString(R.string.call_ended)
        CallEndReason.EXPIRED -> activity.getString(R.string.call_expired)
        CallEndReason.ANSWERED_ELSEWHERE -> activity.getString(R.string.call_answered_elsewhere)
        CallEndReason.ROUTE_LOST -> activity.getString(R.string.call_route_lost)
        null -> activity.getString(R.string.call_ended)
    }

    private fun runNode(action: (Session) -> Unit) = runNode(action) { _, _ -> }

    private fun <T> runNode(action: (Session) -> T, success: (Session, T) -> Unit) {
        NodeHolder.executor.execute {
            val session = NodeHolder.session ?: return@execute
            runCatching { action(session) }
                .onSuccess { value ->
                    activity.runOnUiThread { if (!closed) success(session, value) }
                }
                .onFailure { error ->
                    activity.runOnUiThread {
                        if (!closed) activity.toast(error.message ?: error.toString())
                    }
                }
        }
    }

    @SuppressLint("MissingPermission")
    private fun startMedia(callId: String) {
        if (media?.callId == callId || closed) return
        stopMedia()
        try {
            if (audioManager.requestAudioFocus(focusRequest) != AudioManager.AUDIOFOCUS_REQUEST_GRANTED) {
                throw IllegalStateException(activity.getString(R.string.call_audio_focus_failed))
            }
            audioManager.mode = AudioManager.MODE_IN_COMMUNICATION
            val active = ActiveMedia(callId)
            media = active
            active.start()
        } catch (error: Throwable) {
            stopMedia()
            activity.toast(error.message ?: error.toString())
            runNode { it.hangupCall(callId) }
        }
    }

    private fun stopMedia() {
        media?.close()
        media = null
        audioManager.mode = AudioManager.MODE_NORMAL
        audioManager.abandonAudioFocusRequest(focusRequest)
    }

    @SuppressLint("MissingPermission")
    private inner class ActiveMedia(val callId: String) {
        private val running = AtomicBoolean(true)
        private val executor = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "komms-call-audio").apply { isDaemon = true }
        }
        private val recorder = AudioRecord.Builder()
            .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                    .build(),
            )
            .setBufferSizeInBytes(maxOf(FRAME_BYTES * 4, AudioRecord.getMinBufferSize(
                SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
            )))
            .build()
        private val player = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build(),
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build(),
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .setBufferSizeInBytes(maxOf(FRAME_BYTES * 6, AudioTrack.getMinBufferSize(
                SAMPLE_RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT,
            )))
            .build()
        private val encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        private val decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)

        fun start() {
            encoder.configure(opusFormat(false), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            decoder.configure(opusFormat(true), null, null, 0)
            encoder.start()
            decoder.start()
            recorder.startRecording()
            player.play()
            executor.execute(::captureLoop)
            executor.execute(::playoutLoop)
        }

        private fun captureLoop() {
            val pcm = ByteArray(FRAME_BYTES)
            val info = MediaCodec.BufferInfo()
            try {
                while (running.get()) {
                    var read = 0
                    while (read < pcm.size && running.get()) {
                        val count = recorder.read(pcm, read, pcm.size - read, AudioRecord.READ_BLOCKING)
                        if (count <= 0) break
                        read += count
                    }
                    if (read != pcm.size) continue
                    val input = encoder.dequeueInputBuffer(10_000)
                    if (input >= 0) {
                        encoder.getInputBuffer(input)?.apply { clear(); put(pcm) }
                        encoder.queueInputBuffer(input, 0, pcm.size, System.nanoTime() / 1_000, 0)
                    }
                    drainEncoder(info)
                    pcm.fill(0)
                }
            } finally {
                pcm.fill(0)
            }
        }

        private fun drainEncoder(info: MediaCodec.BufferInfo) {
            while (running.get()) {
                val output = encoder.dequeueOutputBuffer(info, 0)
                if (output < 0) return
                val packet = ByteArray(info.size)
                encoder.getOutputBuffer(output)?.apply {
                    position(info.offset); limit(info.offset + info.size); get(packet)
                }
                encoder.releaseOutputBuffer(output, false)
                try {
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 &&
                        packet.isNotEmpty() && packet.size <= MAX_OPUS_PACKET
                    ) {
                        NodeHolder.session?.sendCallAudio(callId, (info.presentationTimeUs / 1_000).toULong(), packet)
                    }
                } finally {
                    packet.fill(0)
                }
            }
        }

        private fun playoutLoop() {
            val info = MediaCodec.BufferInfo()
            while (running.get()) {
                val frame = runCatching { NodeHolder.session?.takeCallAudio(callId) }.getOrNull()
                if (frame == null) {
                    Thread.sleep(10)
                    continue
                }
                val packet = frame.opusPacket
                try {
                    val input = decoder.dequeueInputBuffer(10_000)
                    if (input >= 0) {
                        decoder.getInputBuffer(input)?.apply { clear(); put(packet) }
                        decoder.queueInputBuffer(input, 0, packet.size, frame.timestampMs.toLong() * 1_000, 0)
                    }
                } finally {
                    packet.fill(0)
                }
                drainDecoder(info)
            }
        }

        private fun drainDecoder(info: MediaCodec.BufferInfo) {
            while (running.get()) {
                val output = decoder.dequeueOutputBuffer(info, 0)
                if (output < 0) return
                val pcm = ByteArray(info.size)
                decoder.getOutputBuffer(output)?.apply {
                    position(info.offset); limit(info.offset + info.size); get(pcm)
                }
                decoder.releaseOutputBuffer(output, false)
                player.write(pcm, 0, pcm.size, AudioTrack.WRITE_BLOCKING)
                pcm.fill(0)
            }
        }

        fun close() {
            if (!running.getAndSet(false)) return
            runCatching { recorder.stop() }
            runCatching { player.pause() }
            executor.shutdownNow()
            runCatching { executor.awaitTermination(250, TimeUnit.MILLISECONDS) }
            runCatching { encoder.stop() }
            runCatching { decoder.stop() }
            encoder.release()
            decoder.release()
            recorder.release()
            player.release()
        }

        private fun opusFormat(decoding: Boolean): MediaFormat =
            MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, SAMPLE_RATE, 1).apply {
                setInteger(MediaFormat.KEY_BIT_RATE, 24_000)
                setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, FRAME_BYTES)
                if (decoding) {
                    setByteBuffer("csd-0", ByteBuffer.wrap(opusHead()))
                    setByteBuffer("csd-1", nanos(0))
                    setByteBuffer("csd-2", nanos(80_000_000))
                }
            }

        private fun nanos(value: Long): ByteBuffer =
            ByteBuffer.allocate(java.lang.Long.BYTES).order(ByteOrder.nativeOrder()).apply {
                putLong(value)
                flip()
            }

        private fun opusHead(): ByteArray = byteArrayOf(
            'O'.code.toByte(), 'p'.code.toByte(), 'u'.code.toByte(), 's'.code.toByte(),
            'H'.code.toByte(), 'e'.code.toByte(), 'a'.code.toByte(), 'd'.code.toByte(),
            1, 1, 0x38, 0x01, 0x80.toByte(), 0xbb.toByte(), 0, 0, 0, 0, 0,
        )
    }

    private companion object {
        const val SAMPLE_RATE = 48_000
        const val FRAME_BYTES = 960 * 2
        const val MAX_OPUS_PACKET = 1_275
    }
}
