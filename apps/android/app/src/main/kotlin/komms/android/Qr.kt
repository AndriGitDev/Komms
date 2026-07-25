package komms.android

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Render camera-safe black-on-white QR text as a crisp bitmap. */
fun qrBitmap(
    text: String,
    size: Int = 720,
    errorCorrection: ErrorCorrectionLevel = ErrorCorrectionLevel.M,
): Bitmap {
    val hints = mapOf(
        EncodeHintType.MARGIN to 1,
        EncodeHintType.ERROR_CORRECTION to errorCorrection,
    )
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
    val pixels = IntArray(size * size)
    for (y in 0 until size) {
        for (x in 0 until size) {
            pixels[y * size + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
        }
    }
    return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.RGB_565)
}

/** Pairing bundles are already authenticated, so use capacity-first level L. */
fun pairingQrBitmap(text: String): Bitmap =
    qrBitmap(text, size = 1_024, errorCorrection = ErrorCorrectionLevel.L)
