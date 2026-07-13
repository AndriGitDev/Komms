// Safety-number verification: both parties see identical digits and an
// identical QR — on any platform. Compare aloud, or scan each other's code;
// a match flips the visible verified badge. Key changes re-open this door.

import KommsCore
import SwiftUI

struct VerifyView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let peer: String

    @State private var sn: SafetyNumber?
    @State private var error: String?
    @State private var scanning = false
    @State private var scanResult: String? // "match" / mismatch message

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if let sn {
                        Text("Compare these digits (or QR) with your contact — they must be identical on both screens.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)

                        Text(sn.display)
                            .font(.body.monospaced())
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)

                        QrCodeView(text: safetyQrText(sn))
                            .frame(width: 220, height: 220)

                        if scanning {
                            QrScannerView { scanned in
                                scanning = false
                                scanResult =
                                    scanned == safetyQrText(sn)
                                    ? "match"
                                    : "MISMATCH — do not trust this session. Their code differs."
                            }
                            .frame(height: 240)
                        } else {
                            Button("Scan their code instead") { scanning = true }
                        }

                        if let scanResult {
                            if scanResult == "match" {
                                Label("Codes match", systemImage: "checkmark.seal.fill")
                                    .foregroundStyle(.green)
                            } else {
                                Text(scanResult)
                                    .foregroundStyle(.red)
                                    .font(.footnote)
                            }
                        }

                        Button("They match — mark verified") {
                            markVerified()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(scanResult != nil && scanResult != "match")
                    } else if let error {
                        Text(error).foregroundStyle(.red)
                    } else {
                        ProgressView()
                    }
                }
                .padding()
            }
            .navigationTitle("Verify")
            .toolbar {
                Button("Close") { dismiss() }
            }
            .task {
                do {
                    sn = try await model.safetyNumber(peer: peer)
                } catch {
                    self.error = errorText(error)
                }
            }
        }
    }

    private func markVerified() {
        Task {
            do {
                try await model.markVerified(peer: peer)
                dismiss()
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
