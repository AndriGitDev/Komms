package komms.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeWakePolicyTest {
    private fun eligible(
        token: String = "token-a",
        preference: NativeWakePreference = NativeWakePreference.GENERIC_VISIBLE,
        permission: NativeWakePermission = NativeWakePermission.GRANTED,
    ) = NativeWakeSnapshot(
        playBuild = true,
        mode = "standard",
        gatewayCount = 1,
        preference = preference,
        permission = permission,
        tokenDigest = token,
        advertised = true,
    )

    @Test
    fun `token rotation and app launch require fresh per-contact capabilities`() {
        val old = eligible()
        assertEquals(
            NativeWakeAction.REGISTER,
            NativeWakePolicy.decide(old, eligible(token = "token-b")).action,
        )
        assertEquals(
            NativeWakeAction.REGISTER,
            NativeWakePolicy.decide(old, old, forceRefresh = true).action,
        )
        assertEquals(NativeWakeAction.NONE, NativeWakePolicy.decide(old, old).action)
    }

    @Test
    fun `permission denial sovereign mode and google-free builds revoke`() {
        val old = eligible()
        assertEquals(
            NativeWakeAction.REVOKE,
            NativeWakePolicy.decide(
                old,
                eligible(permission = NativeWakePermission.DENIED),
            ).action,
        )
        assertEquals(
            NativeWakeAction.REVOKE,
            NativeWakePolicy.decide(old, old.copy(mode = "sovereign")).action,
        )
        assertEquals(
            NativeWakeAction.REVOKE,
            NativeWakePolicy.decide(old, old.copy(playBuild = false)).action,
        )
    }

    @Test
    fun `FCM high priority is limited to exact generic visible profile`() {
        assertTrue(NativeWakePolicy.decide(null, eligible()).highPriorityAllowed)
        assertFalse(
            NativeWakePolicy.decide(
                null,
                eligible(
                    preference = NativeWakePreference.BACKGROUND_ONLY,
                    permission = NativeWakePermission.NOT_REQUIRED,
                ),
            ).highPriorityAllowed,
        )
    }

    @Test
    fun `only static content-free FCM payloads are accepted`() {
        assertTrue(NativeWakePolicy.acceptsStaticPayload(mapOf("wake" to "1"), null, null))
        assertTrue(
            NativeWakePolicy.acceptsStaticPayload(
                mapOf("wake" to "1"),
                "Komms",
                "New activity",
            ),
        )
        assertFalse(
            NativeWakePolicy.acceptsStaticPayload(
                mapOf("wake" to "1", "sender" to "alice"),
                null,
                null,
            ),
        )
        assertFalse(
            NativeWakePolicy.acceptsStaticPayload(
                mapOf("wake" to "1"),
                "Komms",
                "Message from Alice",
            ),
        )
    }

    @Test
    fun `continuation requires bounded remaining work and an unlocked play build`() {
        assertTrue(NativeWakePolicy.shouldScheduleContinuation(true, true, true))
        assertFalse(NativeWakePolicy.shouldScheduleContinuation(false, true, true))
        assertFalse(NativeWakePolicy.shouldScheduleContinuation(true, false, true))
        assertFalse(NativeWakePolicy.shouldScheduleContinuation(true, true, false))
    }
}
