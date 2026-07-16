package komms.android

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Full-screen QR scanner: CameraX frames decoded by ZXing (pure Java — no
 * Play Services). Returns the decoded text as [EXTRA_TEXT].
 */
class ScanActivity : SecureActivity() {
    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private val delivered = AtomicBoolean(false)

    private val requestCamera =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startCamera() else finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            requestCamera.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        analysisExecutor.shutdown()
        super.onDestroy()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.surfaceProvider = findViewById<PreviewView>(R.id.scan_preview).surfaceProvider
            }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(analysisExecutor, QrAnalyzer { text ->
                if (delivered.compareAndSet(false, true)) {
                    runOnUiThread {
                        setResult(RESULT_OK, Intent().putExtra(EXTRA_TEXT, text))
                        finish()
                    }
                }
            })
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(this))
    }

    companion object {
        const val EXTRA_TEXT = "text"

        fun intent(context: Context) = Intent(context, ScanActivity::class.java)
    }
}

/** Decode the Y (luminance) plane of each frame; QR is rotation-agnostic. */
private class QrAnalyzer(private val onText: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    override fun analyze(image: ImageProxy) {
        image.use {
            val plane = it.planes[0]
            val bytes = ByteArray(plane.buffer.remaining())
            plane.buffer.get(bytes)
            val source = PlanarYUVLuminanceSource(
                bytes,
                plane.rowStride, it.height,
                0, 0, it.width, it.height,
                false,
            )
            try {
                val result = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))
                onText(result.text)
            } catch (_: NotFoundException) {
                // No QR in this frame — keep scanning.
            } finally {
                reader.reset()
            }
        }
    }
}
