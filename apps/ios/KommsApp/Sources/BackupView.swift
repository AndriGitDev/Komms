// Root-free backup: one encrypted `.kkr` file shared wherever the user wants
// it. The backup mnemonic is shown once; stable-identity recovery separately
// requires the offline account-authority package and its different phrase.

import KommsCore
import SwiftUI

struct BackupView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var mnemonic: String?
    @State private var fileURL: URL?
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let mnemonic, let fileURL {
                        Text("Your root-free backup is sealed with these 24 backup words. They are shown exactly once and stored nowhere — write them down separately.")
                            .font(.footnote)

                        Text(mnemonic)
                            .font(.body.monospaced())
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.gray.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                            .textSelection(.enabled)

                        ShareLink(item: fileURL) {
                            Label("Save the backup file…", systemImage: "square.and.arrow.up")
                        }

                        Text("Restoring the stable identity also needs the separately held offline .kra authority file and its different 24 words. Live device, ratchet, rendezvous, wake, group, and delivery secrets are excluded; recovery starts a fresh epoch and re-handshakes.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Writes one root-free encrypted file carrying the stable public identity, contacts, and non-ephemeral history. It cannot recover the identity without the separately held offline authority.")
                            .font(.footnote)

                        if let error {
                            Text(error).foregroundStyle(.red).font(.footnote)
                        }

                        Button(action: export) {
                            if working { ProgressView() } else { Text("Create backup") }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(working)
                    }
                }
                .padding()
            }
            .navigationTitle("Backup")
            .toolbar {
                Button("Done") { dismiss() }
            }
        }
        .interactiveDismissDisabled(mnemonic != nil)
    }

    private func export() {
        error = nil
        working = true
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-backup-\(UUID().uuidString)", isDirectory: true)
        let file = dir.appendingPathComponent("komms-backup.kkr")
        Task {
            defer { working = false }
            do {
                try FileManager.default.createDirectory(
                    at: dir, withIntermediateDirectories: true)
                let words = try await model.exportBackup(to: file)
                fileURL = file
                mnemonic = words
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
