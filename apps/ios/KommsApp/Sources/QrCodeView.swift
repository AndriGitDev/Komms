// QR rendering via CoreImage — no third-party dependencies. Payloads are
// uppercase hex, which keeps the QR in its compact alphanumeric mode
// (interoperable with the desktop and Android apps).

import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct QrCodeView: View {
    let text: String

    var body: some View {
        if let image = Self.render(text) {
            Image(uiImage: image)
                .interpolation(.none) // crisp modules, no smoothing
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR code")
        } else {
            Text("QR generation failed")
                .foregroundStyle(.red)
        }
    }

    private static func render(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        // Scale up so the resizable Image has real pixels to work with.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        guard
            let cg = CIContext().createCGImage(scaled, from: scaled.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}
