package komms.android

import java.io.File
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import komms.core.EventSink
import komms.core.Session
import uniffi.kult_ffi.DeliveryState
import uniffi.kult_ffi.Event

/**
 * Process-wide home of the running [Session]. Activities come and go
 * (rotation, backstack); the node does not. All node calls are blocking, so
 * they run on [executor] — a single thread, mirroring how the FFI runtime
 * serializes commands anyway.
 */
object NodeHolder {
    @Volatile
    var session: Session? = null
        private set

    /**
     * First-run authority export is a process-memory-only gate. Keeping this
     * state here lets an Activity recreation resume without persisting the
     * one-time phrase or allowing the main UI through early.
     */
    @Volatile
    var recoveryAuthorityOnboardingPending: Boolean = false
        private set

    @Volatile
    var stagedRecoveryAuthority: File? = null
        private set

    @Volatile
    var stagedRecoveryAuthorityMnemonic: String? = null
        private set

    @Volatile
    var recoveryAuthorityWritten: Boolean = false
        private set

    /** The one thread every blocking node call runs on. */
    val executor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "komms-node").apply { isDaemon = true }
    }

    private val listeners = CopyOnWriteArrayList<(Event) -> Unit>()

    /**
     * Message ids the node reported as held for a faster link
     * ([Event.AwaitingFasterLink]) — the chat screen renders the honest
     * "held" verdict for these until a delivery update clears it.
     */
    val held: MutableSet<String> = Collections.newSetFromMap(ConcurrentHashMap())

    /** The sink handed to [Session.open]; fans out to screen listeners. */
    val sink: EventSink = { event ->
        when (event) {
            is Event.AwaitingFasterLink -> held.add(event.id)
            is Event.DeliveryUpdated ->
                if (event.state != DeliveryState.QUEUED) held.remove(event.id)
            is Event.ThemeChanged -> session?.let { active ->
                executor.execute { ThemeController.reconcile(active) }
            }
            else -> {}
        }
        for (listener in listeners) listener(event)
    }

    fun attach(session: Session) {
        this.session = session
    }

    fun beginRecoveryAuthorityOnboarding() {
        recoveryAuthorityOnboardingPending = true
    }

    fun stageRecoveryAuthority(file: File, mnemonic: String) {
        stagedRecoveryAuthority = file
        stagedRecoveryAuthorityMnemonic = mnemonic
        recoveryAuthorityWritten = false
    }

    fun markRecoveryAuthorityWritten() {
        recoveryAuthorityWritten = true
    }

    fun completeRecoveryAuthorityOnboarding() {
        stagedRecoveryAuthority?.delete()
        stagedRecoveryAuthority = null
        stagedRecoveryAuthorityMnemonic = null
        recoveryAuthorityWritten = false
        recoveryAuthorityOnboardingPending = false
    }

    /**
     * Lock: forget the session immediately (so the gate shows), then stop
     * the node off-thread — `stop` blocks until the runtime is down.
     */
    fun stopAndClear() {
        val stopping = session
        session = null
        held.clear()
        stagedRecoveryAuthority?.delete()
        stagedRecoveryAuthority = null
        stagedRecoveryAuthorityMnemonic = null
        recoveryAuthorityWritten = false
        recoveryAuthorityOnboardingPending = false
        stopping?.let { executor.execute { it.stop() } }
    }

    /** Events arrive on the FFI runtime's thread — marshal in the listener. */
    fun addListener(listener: (Event) -> Unit) = listeners.add(listener)

    fun removeListener(listener: (Event) -> Unit) = listeners.remove(listener)
}
