package komms.android

import android.content.pm.ServiceInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class NodeServiceTest {
    @Test
    fun `android 14 and newer use untimed remote messaging service`() {
        for (sdk in 34..35) {
            assertEquals(
                ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING,
                NodeService.foregroundServiceType(sdk),
            )
        }
    }

    @Test
    fun `older versions retain compatible data sync service`() {
        for (sdk in 26..33) {
            assertEquals(
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                NodeService.foregroundServiceType(sdk),
            )
        }
    }
}
