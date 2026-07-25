// QR rendering via CoreImage — no third-party dependencies.

import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct QrCodeView: View {
    let text: String
    var correctionLevel = "M"

    var body: some View {
        if let image = Self.render(text, correctionLevel: correctionLevel) {
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

    private static func render(_ text: String, correctionLevel: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = correctionLevel
        guard let output = filter.outputImage else { return nil }
        // Scale up so the resizable Image has real pixels to work with.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        guard
            let cg = CIContext().createCGImage(scaled, from: scaled.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}
