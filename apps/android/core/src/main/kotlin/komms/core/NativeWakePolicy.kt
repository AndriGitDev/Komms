package komms.core

/** Recipient-selected static native-notification profile. */
enum class NativeWakePreference {
    DISABLED,
    BACKGROUND_ONLY,
    GENERIC_VISIBLE,
}

/** Android notification authorization relevant to a visible wake. */
enum class NativeWakePermission {
    NOT_REQUIRED,
    GRANTED,
    DENIED,
}

/** Platform action required after a lifecycle transition. */
enum class NativeWakeAction {
    NONE,
    REGISTER,
    REVOKE,
}

/** Secret-free lifecycle facts used to decide native-wake capability state. */
data class NativeWakeSnapshot(
    val playBuild: Boolean,
    val mode: String,
    val gatewayCount: Int,
    val preference: NativeWakePreference,
    val permission: NativeWakePermission,
    val tokenDigest: String?,
    val advertised: Boolean,
)

/** One bounded platform decision. */
data class NativeWakeDecision(
    val action: NativeWakeAction,
    val advertise: Boolean,
    val highPriorityAllowed: Boolean,
)

/**
 * Android lifecycle policy kept independent of Firebase and Android APIs so
 * Google-free builds and host tests consume the same decision table.
 */
object NativeWakePolicy {
    fun decide(
        previous: NativeWakeSnapshot?,
        current: NativeWakeSnapshot,
        forceRefresh: Boolean = false,
    ): NativeWakeDecision {
        require(current.mode in setOf("standard", "private", "sovereign"))
        val eligible =
            current.playBuild &&
                current.mode != "sovereign" &&
                current.gatewayCount in 1..4 &&
                current.preference != NativeWakePreference.DISABLED &&
                current.tokenDigest != null &&
                (
                    current.preference != NativeWakePreference.GENERIC_VISIBLE ||
                        current.permission == NativeWakePermission.GRANTED
                    )
        if (!eligible) {
            return NativeWakeDecision(
                action = if (previous?.advertised == true || current.advertised) {
                    NativeWakeAction.REVOKE
                } else {
                    NativeWakeAction.NONE
                },
                advertise = false,
                highPriorityAllowed = false,
            )
        }
        val changed =
            previous == null ||
                previous.tokenDigest != current.tokenDigest ||
                previous.preference != current.preference ||
                previous.mode != current.mode ||
                previous.gatewayCount != current.gatewayCount ||
                !previous.advertised
        return NativeWakeDecision(
            action = if (changed || forceRefresh) NativeWakeAction.REGISTER else NativeWakeAction.NONE,
            advertise = true,
            highPriorityAllowed = current.preference == NativeWakePreference.GENERIC_VISIBLE,
        )
    }

    /** Accept only the two content-free FCM shapes emitted by the gateway. */
    fun acceptsStaticPayload(
        data: Map<String, String>,
        notificationTitle: String?,
        notificationBody: String?,
    ): Boolean {
        if (data != mapOf("wake" to "1")) return false
        return (notificationTitle == null && notificationBody == null) ||
            (notificationTitle == "Komms" && notificationBody == "New activity")
    }

    /** Continuation is scheduled only for bounded unprocessed core work. */
    fun shouldScheduleContinuation(
        remaining: Boolean,
        sessionUnlocked: Boolean,
        playBuild: Boolean,
    ): Boolean = remaining && sessionUnlocked && playBuild
}
