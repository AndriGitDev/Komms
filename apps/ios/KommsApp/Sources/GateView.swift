// The gate: create/unlock the encrypted store, or restore a `.kkr` backup
// with its 24-word mnemonic. Network settings are editable here too — they
// apply when the node starts.

import KommsCore
import SwiftUI
import UniformTypeIdentifiers

struct GateView: View {
    @EnvironmentObject private var model: AppModel

    private enum Mode: String, CaseIterable {
        case unlock = "Unlock"
        case restore = "Restore"
    }

    @State private var mode: Mode = .unlock
    @State private var passphrase = ""
    @State private var mnemonic = ""
    @State private var backupURL: URL?
    @State private var pickingBackup = false
    @State private var showSettings = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Picker("Mode", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)

                Section {
                    SecureField(
                        model.storeExists || mode == .restore
                            ? "Passphrase" : "New passphrase",
                        text: $passphrase)
                } footer: {
                    Text(
                        mode == .restore
                            ? "Restoring creates a fresh store sealed with this passphrase."
                            : model.storeExists
                                ? "Unlock your encrypted store."
                                : "First run: this passphrase seals a new encrypted store.")
                }

                if mode == .restore {
                    Section("Backup") {
                        Button(backupURL?.lastPathComponent ?? "Choose backup file (.kkr)…") {
                            pickingBackup = true
                        }
                        TextField("24-word mnemonic", text: $mnemonic, axis: .vertical)
                            .lineLimit(3...5)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }

                Section {
                    Button(action: go) {
                        if working {
                            ProgressView()
                        } else {
                            Text(
                                mode == .restore
                                    ? "Restore and start"
                                    : model.storeExists ? "Unlock" : "Create")
                        }
                    }
                    .disabled(working || passphrase.isEmpty)
                }
            }
            .navigationTitle("Komms")
            .toolbar {
                Button("Network settings") { showSettings = true }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
            .fileImporter(isPresented: $pickingBackup, allowedContentTypes: [.data]) {
                if case let .success(url) = $0 { backupURL = url }
            }
        }
    }

    private func go() {
        error = nil
        working = true
        let pass = passphrase
        Task {
            defer { working = false }
            do {
                if mode == .restore {
                    guard let backupURL else {
                        error = "choose a backup file first"
                        return
                    }
                    let scoped = backupURL.startAccessingSecurityScopedResource()
                    defer { if scoped { backupURL.stopAccessingSecurityScopedResource() } }
                    try await model.restore(
                        backup: backupURL, mnemonic: mnemonic, passphrase: pass)
                } else {
                    try await model.unlock(passphrase: pass)
                }
                passphrase = ""
                mnemonic = ""
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
