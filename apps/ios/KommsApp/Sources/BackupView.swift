// Backup: one encrypted `.kkr` file (ADR-0011), shared wherever the user
// wants it via the system share sheet. The sealing mnemonic is shown exactly
// once and stored nowhere — write it down, then dismiss.

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
                        Text("Your backup is sealed with these 24 words. They are shown exactly once and stored nowhere — write them down on paper.")
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

                        Text("Restoring needs the file and the words. Ratchet sessions are deliberately not included — a restored node re-handshakes with your contacts automatically.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Writes one encrypted file carrying your identity, contacts, and history. Anyone with the file still needs the 24-word mnemonic it is sealed with.")
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
