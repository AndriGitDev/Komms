// Camera QR scanning via AVFoundation's metadata output — no third-party
// dependencies, no Vision/ML. Hands the decoded string back once and stops.

import AVFoundation
import KommsCore
import SwiftUI
import UIKit

struct QrScannerView: UIViewControllerRepresentable {
    /// Called once, on the main thread, with the decoded QR payload.
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onScan = onScan
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?

    private let session = AVCaptureSession()
    private let bundleAssembler = BundleQrAssembler()
    private let progressLabel = UILabel()
    private var delivered = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard
            let device = AVCaptureDevice.default(for: .video),
            let input = try? AVCaptureDeviceInput(device: device),
            session.canAddInput(input)
        else {
            showUnavailable("Camera unavailable")
            return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            showUnavailable("Camera unavailable")
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.layer.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        progressLabel.text = "Point at a Komms QR"
        progressLabel.textColor = .white
        progressLabel.backgroundColor = UIColor.black.withAlphaComponent(0.8)
        progressLabel.font = .preferredFont(forTextStyle: .headline)
        progressLabel.textAlignment = .center
        progressLabel.layer.cornerRadius = 10
        progressLabel.clipsToBounds = true
        progressLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(progressLabel)
        NSLayoutConstraint.activate([
            progressLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            progressLabel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            progressLabel.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor, constant: -40),
            progressLabel.heightAnchor.constraint(greaterThanOrEqualToConstant: 44),
        ])
    }

    private func showUnavailable(_ text: String) {
        let label = UILabel()
        label.text = text
        label.textColor = .white
        label.textAlignment = .center
        label.frame = view.bounds
        label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(label)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        view.layer.sublayers?.first { $0 is AVCaptureVideoPreviewLayer }?
            .frame = view.layer.bounds
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard
            !delivered,
            let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
            object.type == .qr,
            let text = object.stringValue,
            let progress = bundleAssembler.accept(text)
        else { return }
        guard let complete = progress.completeText else {
            progressLabel.text = "Pairing frames \(progress.received) of \(progress.total)"
            return
        }
        delivered = true
        session.stopRunning()
        onScan?(complete)
    }
}
