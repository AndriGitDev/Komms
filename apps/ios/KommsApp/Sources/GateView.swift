// The gate: create/unlock the encrypted store, or restore a `.kkr` backup
// with its 24-word mnemonic. Network settings remain available as an
// advanced action, without competing with the primary unlock flow.

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
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    VStack(alignment: .leading, spacing: 12) {
                        KommsBrandLockup()
                        Text("Private messaging that keeps working.")
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(ThemePalette.textPrimary)
                        Text("Your identity and conversations stay encrypted on this device. No central account required.")
                            .font(.subheadline)
                            .foregroundStyle(ThemePalette.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    VStack(spacing: 18) {
                        Picker("Mode", selection: $mode) {
                            ForEach(Mode.allCases, id: \.self) { Text($0.rawValue) }
                        }
                        .pickerStyle(.segmented)

                        VStack(alignment: .leading, spacing: 8) {
                            Text(passphraseLabel)
                                .font(.subheadline.weight(.semibold))
                            SecureField(passphraseLabel, text: $passphrase)
                                .incognitoKeyboard()
                                .padding(12)
                                .background(ThemePalette.background,
                                            in: RoundedRectangle(cornerRadius: 10))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(ThemePalette.border, lineWidth: 1)
                                }
                            Text(passphraseHelp)
                                .font(.footnote)
                                .foregroundStyle(ThemePalette.textSecondary)
                        }

                        if mode == .restore {
                            Divider()
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Encrypted backup")
                                    .font(.subheadline.weight(.semibold))
                                Button {
                                    pickingBackup = true
                                } label: {
                                    Label(
                                        backupURL?.lastPathComponent ?? "Choose backup file (.kkr)",
                                        systemImage: "doc.badge.plus")
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .buttonStyle(.bordered)

                                SecureField("24-word recovery phrase", text: $mnemonic)
                                    .incognitoKeyboard()
                                    .padding(12)
                                    .background(ThemePalette.background,
                                                in: RoundedRectangle(cornerRadius: 10))
                                    .overlay {
                                        RoundedRectangle(cornerRadius: 10)
                                            .stroke(ThemePalette.border, lineWidth: 1)
                                    }
                            }
                        }

                        if let error {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote)
                                .foregroundStyle(ThemePalette.danger)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }

                        Button(action: go) {
                            HStack {
                                if working { ProgressView().tint(ThemePalette.onAccent) }
                                Text(primaryAction)
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 5)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(ThemePalette.accent)
                        .foregroundStyle(ThemePalette.onAccent)
                        .disabled(working || passphrase.isEmpty)
                    }
                    .padding(20)
                    .background(ThemePalette.surface, in: RoundedRectangle(cornerRadius: 22))
                    .overlay {
                        RoundedRectangle(cornerRadius: 22)
                            .stroke(ThemePalette.border, lineWidth: 1)
                    }

                    Button {
                        showSettings = true
                    } label: {
                        Label("Advanced network settings", systemImage: "network")
                            .font(.subheadline)
                    }
                    .frame(maxWidth: .infinity)

                    Text("Komms can use the internet, your local network, or an attached mesh radio. Transport details remain under your control.")
                        .font(.footnote)
                        .foregroundStyle(ThemePalette.textSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 30)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
            }
            .background(ThemePalette.background)
            .navigationBarHidden(true)
            .sheet(isPresented: $showSettings) {
                NavigationStack {
                    AdvancedNetworkSettingsView()
                        .toolbar {
                            Button("Cancel") { showSettings = false }
                        }
                }
            }
            .fileImporter(isPresented: $pickingBackup, allowedContentTypes: [.data]) {
                if case let .success(url) = $0 { backupURL = url }
            }
            .overlay {
                if working { startupOverlay }
            }
        }
    }

    private var passphraseLabel: String {
        model.storeExists || mode == .restore ? "Passphrase" : "Create a passphrase"
    }

    private var passphraseHelp: String {
        if mode == .restore {
            return "Your restored store will be sealed with this passphrase."
        }
        return model.storeExists
            ? "Unlock your encrypted store on this device."
            : "This passphrase protects the new encrypted store on this device."
    }

    private var primaryAction: String {
        mode == .restore ? "Restore and start" : model.storeExists ? "Unlock Komms" : "Create Komms"
    }

    private var startupOverlay: some View {
        ZStack {
            ThemePalette.deep.opacity(0.78).ignoresSafeArea()
            VStack(spacing: 16) {
                KommsMark()
                    .frame(width: 58, height: 58)
                ProgressView()
                    .controlSize(.large)
                    .tint(ThemePalette.brand)
                Text("Decrypting and starting your node")
                    .font(.headline)
                Text("This can take up to 30 seconds. Keep Komms open while it securely unlocks your store and joins the network.")
                    .font(.subheadline)
                    .foregroundStyle(Color.white.opacity(0.76))
                    .multilineTextAlignment(.center)
            }
            .foregroundStyle(.white)
            .padding(26)
            .frame(maxWidth: 360)
            .background(Color(
                red: Double(0x15) / 255,
                green: Double(0x37) / 255,
                blue: Double(0x46) / 255),
                        in: RoundedRectangle(cornerRadius: 22))
            .overlay {
                RoundedRectangle(cornerRadius: 22)
                    .stroke(ThemePalette.brand.opacity(0.45), lineWidth: 1)
            }
            .padding(24)
            .accessibilityElement(children: .combine)
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
                        error = "Choose a backup file first."
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
