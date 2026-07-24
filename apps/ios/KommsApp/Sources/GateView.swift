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
                        .incognitoKeyboard()
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
                        SecureField("24-word mnemonic", text: $mnemonic)
                            .incognitoKeyboard()
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
            .overlay {
                if working {
                    ZStack {
                        Color.black.opacity(0.45)
                            .ignoresSafeArea()
                        VStack(spacing: 14) {
                            ProgressView()
                                .controlSize(.large)
                            Text("Starting Komms")
                                .font(.headline)
                            Text(
                                "Opening your encrypted store and starting the node can take up to 30 seconds. Keep Komms open while this finishes."
                            )
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                        }
                        .padding(24)
                        .frame(maxWidth: 360)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                        .padding(24)
                        .accessibilityElement(children: .combine)
                    }
                }
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
