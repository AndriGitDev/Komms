package komms.android

import android.Manifest
import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import komms.core.NativeWakeAction
import komms.core.NativeWakePermission
import komms.core.NativeWakePolicy
import komms.core.NativeWakePreference
import komms.core.NativeWakeSnapshot
import komms.core.NetworkSettings
import uniffi.kult_ffi.NativeWakeEnvironment
import uniffi.kult_ffi.NativeWakePlatform as FfiNativeWakePlatform
import uniffi.kult_ffi.NativeWakeProfile

/**
 * Process-local bridge between Android lifecycle callbacks and the shared
 * core contract. Provider tokens stay only in process memory and the fixed
 * gateway registration body; preferences and WorkManager input carry none.
 */
object NativeWakeManager {
    private const val REGISTRATION_WORK = "komms-native-wake-registration"
    private const val COLLECTION_WORK = "komms-native-wake-collection"
    private const val COLLECTION_BUDGET_MS = 20_000u
    private const val CONTINUATION_BUDGET_MS = 10_000u

    private val tokenLock = Any()
    private var providerToken: ByteArray? = null
    private var lastSnapshot: NativeWakeSnapshot? = null
    private var networkConfigurationStale = false
    private val registrationInFlight = AtomicBoolean()
    private val registrationPending = AtomicBoolean()
    private val collectionInFlight = AtomicBoolean()

    fun onApplicationStart(context: Context) {
        NativeWakePlatform.requestCurrentToken(context.applicationContext) { token ->
            if (token == null) {
                reconcile(context, forceRefresh = false)
            } else {
                updateToken(context, token)
            }
        }
    }

    fun onSessionAvailable(context: Context) {
        synchronized(tokenLock) {
            networkConfigurationStale = false
        }
        reconcile(context, forceRefresh = true)
        onApplicationStart(context)
    }

    fun onRelationshipChanged(context: Context) {
        reconcile(context, forceRefresh = true)
    }

    fun onPermissionChanged(context: Context) {
        reconcile(context, forceRefresh = false)
    }

    /**
     * Revoke against the currently running configuration and defer fresh
     * registration until the next unlock loads the saved provider set.
     */
    fun onNetworkSettingsChanged(context: Context) {
        synchronized(tokenLock) {
            networkConfigurationStale = true
        }
        reconcile(context, forceRefresh = false)
    }

    fun updateToken(context: Context, token: ByteArray) {
        if (token.isEmpty() || token.size > 512) return
        synchronized(tokenLock) {
            providerToken?.fill(0)
            providerToken = token.copyOf()
        }
        reconcile(context, forceRefresh = true)
    }

    fun clearToken() {
        synchronized(tokenLock) {
            providerToken?.fill(0)
            providerToken = null
            lastSnapshot = null
        }
    }

    fun handleWake(context: Context) {
        val session = NodeHolder.session ?: return
        if (!collectionInFlight.compareAndSet(false, true)) return
        NodeHolder.executor.execute {
            try {
                session.collectAfterNativeWake(COLLECTION_BUDGET_MS)
            } catch (_: Exception) {
                // The durable ordinary queue and mailbox schedule remain authoritative.
            } finally {
                collectionInFlight.set(false)
                scheduleCollectionContinuation(context)
            }
        }
    }

    fun handleVisibleWakeIntent(context: Context, intent: Intent?) {
        val extras = intent?.extras ?: return
        if (extras.getString("wake") != "1") return
        val forbidden = setOf(
            "sender", "account", "conversation", "message", "text",
            "media", "unread", "timestamp",
        )
        if (forbidden.any(extras::containsKey)) return
        intent.removeExtra("wake")
        handleWake(context)
    }

    internal fun continueRegistration(context: Context): Boolean =
        performRegistration(context.applicationContext, forceRefresh = true)

    internal fun continueCollection() {
        val session = NodeHolder.session ?: return
        try {
            session.collectAfterNativeWake(CONTINUATION_BUDGET_MS)
        } catch (_: Exception) {
            // Android may stop or defer this work; persisted remainder stays queued.
        }
    }

    private fun reconcile(context: Context, forceRefresh: Boolean) {
        if (registrationInFlight.get()) {
            registrationPending.set(true)
            return
        }
        val app = context.applicationContext
        NodeHolder.executor.execute {
            performRegistration(app, forceRefresh)
        }
    }

    private fun performRegistration(context: Context, forceRefresh: Boolean): Boolean {
        val session = NodeHolder.session ?: return false
        if (!registrationInFlight.compareAndSet(false, true)) {
            registrationPending.set(true)
            return false
        }
        var remaining = false
        var tokenCopy: ByteArray? = null
        try {
            val settings = runCatching {
                NetworkSettings.load(KommsApp.dataDir(context.applicationContext as Application))
            }.getOrDefault(NetworkSettings())
            val preference = NativeWakePreferences(context).load()
            tokenCopy = synchronized(tokenLock) { providerToken?.copyOf() }
            val digest = tokenCopy?.let(::digest)
            val permission = when {
                preference != NativeWakePreference.GENERIC_VISIBLE ->
                    NativeWakePermission.NOT_REQUIRED
                Build.VERSION.SDK_INT < 33 ||
                    context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                    PackageManager.PERMISSION_GRANTED -> NativeWakePermission.GRANTED
                else -> NativeWakePermission.DENIED
            }
            val prior = synchronized(tokenLock) { lastSnapshot }
            val current = NativeWakeSnapshot(
                playBuild = NativeWakePlatform.supported(context),
                mode = settings.mode,
                gatewayCount = settings.wake.size,
                preference = preference,
                permission = permission,
                tokenDigest = digest,
                // On process start, conservatively assume sealed issued state
                // may exist so a disabled path publishes explicit revocation.
                advertised = prior?.advertised ?: true,
            )
            if (synchronized(tokenLock) { networkConfigurationStale }) {
                session.revokeNativeWake()
                synchronized(tokenLock) {
                    lastSnapshot = current.copy(advertised = false)
                }
                return false
            }
            val decision = NativeWakePolicy.decide(prior, current, forceRefresh)
            when (decision.action) {
                NativeWakeAction.REGISTER -> {
                    val exactToken = tokenCopy ?: return false
                    try {
                        val result = session.registerNativeWake(
                            platform = FfiNativeWakePlatform.FCM,
                            environment = if (BuildConfig.DEBUG) {
                                NativeWakeEnvironment.DEVELOPMENT
                            } else {
                                NativeWakeEnvironment.PRODUCTION
                            },
                            profile = if (
                                preference == NativeWakePreference.GENERIC_VISIBLE
                            ) {
                                NativeWakeProfile.GENERIC_VISIBLE
                            } else {
                                NativeWakeProfile.BACKGROUND_ONLY
                            },
                            providerToken = exactToken,
                            appTopic = context.packageName,
                        )
                        remaining = result.remaining
                        synchronized(tokenLock) {
                            lastSnapshot = current.copy(advertised = true)
                        }
                    } finally {
                        exactToken.fill(0)
                    }
                }
                NativeWakeAction.REVOKE -> {
                    session.revokeNativeWake()
                    synchronized(tokenLock) {
                        lastSnapshot = current.copy(advertised = false)
                    }
                }
                NativeWakeAction.NONE -> synchronized(tokenLock) {
                    lastSnapshot = current.copy(advertised = decision.advertise)
                }
            }
        } catch (_: Exception) {
            // Optional wake failure cannot block or relabel ordinary delivery.
        } finally {
            tokenCopy?.fill(0)
            registrationInFlight.set(false)
            if (registrationPending.getAndSet(false)) {
                reconcile(context, forceRefresh = true)
            }
        }
        if (
            NativeWakePolicy.shouldScheduleContinuation(
                remaining = remaining,
                sessionUnlocked = NodeHolder.session != null,
                playBuild = NativeWakePlatform.supported(context),
            )
        ) {
            scheduleRegistrationContinuation(context)
        }
        return remaining
    }

    private fun scheduleRegistrationContinuation(context: Context) {
        val request = OneTimeWorkRequestBuilder<NativeWakeRegistrationWorker>()
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            REGISTRATION_WORK,
            ExistingWorkPolicy.REPLACE,
            request,
        )
    }

    private fun scheduleCollectionContinuation(context: Context) {
        if (!NativeWakePlatform.supported(context) || NodeHolder.session == null) return
        val request = OneTimeWorkRequestBuilder<NativeWakeCollectionWorker>()
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            COLLECTION_WORK,
            ExistingWorkPolicy.KEEP,
            request,
        )
    }

    private fun networkConstraints(): Constraints =
        Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

    private fun digest(token: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(token)
            .joinToString(separator = "") { "%02x".format(it.toInt() and 0xff) }
}
