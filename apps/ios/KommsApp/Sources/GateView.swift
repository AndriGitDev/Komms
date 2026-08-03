// The gate: create/unlock the encrypted store, or restore a root-free `.kkr`
// backup with its mnemonic and the separately held offline account authority.

import KommsCore
import SwiftUI
import UniformTypeIdentifiers

private enum AuthorityUpgradeKind: String, Identifiable {
    case migration
    case reset
    case legacyBackupReset

    var id: String { rawValue }
}

struct GateView: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage("komms.locale") private var localePreference = "system"

    private enum Mode: CaseIterable {
        case unlock
        case restore

        var title: String {
            switch self {
            case .unlock: return L10n.source("Unlock")
            case .restore: return L10n.source("Restore")
            }
        }
    }

    @State private var mode: Mode = .unlock
    @State private var passphrase = ""
    @State private var mnemonic = ""
    @State private var backupURL: URL?
    @State private var pickingBackup = false
    @State private var recoveryAuthorityURL: URL?
    @State private var recoveryMnemonic = ""
    @State private var pickingRecoveryAuthority = false
    @State private var legacyBackup = false
    @State private var showSettings = false
    @State private var working = false
    @State private var error: String?
    @State private var authorityUpgrade: AuthorityUpgradeKind?

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
                        Picker(
                            L10n.text("language_title"),
                            selection: $localePreference
                        ) {
                            Text(L10n.text("language_system")).tag("system")
                            Text(L10n.text("language_english")).tag("en-US")
                            Text(L10n.text("language_icelandic")).tag("is")
                        }
                        .pickerStyle(.menu)
                        .accessibilityHint(L10n.text("language_note"))
                    }

                    VStack(spacing: 18) {
                        Picker("Mode", selection: $mode) {
                            ForEach(Mode.allCases, id: \.self) { Text($0.title) }
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
                                Text(legacyBackup
                                     ? L10n.source("Legacy copied-root backup")
                                     : L10n.source("Root-free encrypted backup"))
                                    .font(.subheadline.weight(.semibold))
                                Button {
                                    pickingBackup = true
                                } label: {
                                    Label(
                                        backupURL?.lastPathComponent
                                            ?? L10n.source("Choose backup file (.kkr)"),
                                        systemImage: "doc.badge.plus")
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .buttonStyle(.bordered)

                                SecureField("24-word backup mnemonic", text: $mnemonic)
                                    .incognitoKeyboard()
                                    .padding(12)
                                    .background(ThemePalette.background,
                                                in: RoundedRectangle(cornerRadius: 10))
                                    .overlay {
                                        RoundedRectangle(cornerRadius: 10)
                                            .stroke(ThemePalette.border, lineWidth: 1)
                                    }

                                Toggle(
                                    "This is a legacy KKR1–KKR7 copied-root backup",
                                    isOn: $legacyBackup)

                                if !legacyBackup {
                                    Button {
                                        pickingRecoveryAuthority = true
                                    } label: {
                                        Label(
                                            recoveryAuthorityURL?.lastPathComponent
                                                ?? L10n.source(
                                                    "Choose offline authority file (.kra)"),
                                            systemImage: "externaldrive.badge.checkmark")
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                    .buttonStyle(.bordered)

                                    SecureField(
                                        "Different 24-word authority mnemonic",
                                        text: $recoveryMnemonic
                                    )
                                    .incognitoKeyboard()
                                    .padding(12)
                                    .background(ThemePalette.background,
                                                in: RoundedRectangle(cornerRadius: 10))
                                    .overlay {
                                        RoundedRectangle(cornerRadius: 10)
                                            .stroke(ThemePalette.border, lineWidth: 1)
                                    }
                                }

                                Text(legacyBackup
                                     ? L10n.source(
                                        "The former address cannot safely resume. Komms will require a fresh identity, preserve only a clearly marked local archive and petnames, clear routes and trust, and require every contact to compare a new safety number.")
                                     : L10n.source(
                                        "The backup excludes live device, session, rendezvous, and offline-authority secrets. Stable-identity recovery requires both separately held files and their different phrases."))
                                    .font(.footnote)
                                    .foregroundStyle(
                                        legacyBackup
                                            ? ThemePalette.danger
                                            : ThemePalette.textSecondary)
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
            .fileImporter(
                isPresented: $pickingRecoveryAuthority,
                allowedContentTypes: [.data]
            ) {
                if case let .success(url) = $0 { recoveryAuthorityURL = url }
            }
            .overlay {
                if working { startupOverlay }
            }
            .sheet(item: $authorityUpgrade) { kind in
                AuthorityUpgradeView(
                    kind: kind,
                    passphrase: passphrase,
                    legacyBackupURL: backupURL,
                    legacyBackupMnemonic: mnemonic)
                    .environmentObject(model)
            }
        }
    }

    private var passphraseLabel: String {
        model.storeExists || mode == .restore
            ? L10n.source("Passphrase")
            : L10n.source("Create a passphrase")
    }

    private var passphraseHelp: String {
        if mode == .restore {
            return L10n.source(
                "Your restored store will be sealed with this passphrase.")
        }
        return model.storeExists
            ? L10n.source("Unlock your encrypted store on this device.")
            : L10n.source(
                "This passphrase protects the new encrypted store on this device.")
    }

    private var primaryAction: String {
        mode == .restore
            ? L10n.source("Restore and start")
            : model.storeExists
                ? L10n.source("Unlock Komms")
                : L10n.source("Create Komms")
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
                Text("Starting Komms")
                    .font(.headline)
                Text("Opening your encrypted store and starting the node can take up to 30 seconds. Keep Komms open while it securely joins the network.")
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
                        error = L10n.source("Choose a backup file first.")
                        return
                    }
                    if legacyBackup {
                        authorityUpgrade = .legacyBackupReset
                        return
                    }
                    guard let recoveryAuthorityURL else {
                        error = L10n.source(
                            "Choose the separately held offline authority file.")
                        return
                    }
                    let backupScoped = backupURL.startAccessingSecurityScopedResource()
                    let authorityScoped =
                        recoveryAuthorityURL.startAccessingSecurityScopedResource()
                    defer {
                        if backupScoped { backupURL.stopAccessingSecurityScopedResource() }
                        if authorityScoped {
                            recoveryAuthorityURL.stopAccessingSecurityScopedResource()
                        }
                    }
                    try await model.restore(
                        backup: backupURL,
                        mnemonic: mnemonic,
                        recoveryAuthority: recoveryAuthorityURL,
                        recoveryMnemonic: recoveryMnemonic,
                        passphrase: pass)
                } else {
                    try await model.unlock(passphrase: pass)
                }
                passphrase = ""
                mnemonic = ""
                recoveryMnemonic = ""
            } catch {
                let text = errorText(error)
                if text.contains("explicit offline-authority migration is required") {
                    authorityUpgrade = .migration
                } else if text.contains("authority reset with a new identity is required") {
                    authorityUpgrade = .reset
                } else {
                    self.error = text
                }
            }
        }
    }
}

private struct AuthorityUpgradeView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var model: AppModel

    let passphrase: String
    let legacyBackupURL: URL?
    let legacyBackupMnemonic: String

    @State private var kind: AuthorityUpgradeKind
    @State private var mnemonic: String?
    @State private var newAddress: String?
    @State private var document: RecoveryAuthorityDocument?
    @State private var stagedURL: URL?
    @State private var exportingFile = false
    @State private var saved = false
    @State private var identityChangeConfirmed = false
    @State private var working = false
    @State private var completed = false
    @State private var error: String?

    init(
        kind: AuthorityUpgradeKind,
        passphrase: String,
        legacyBackupURL: URL? = nil,
        legacyBackupMnemonic: String = ""
    ) {
        self.passphrase = passphrase
        self.legacyBackupURL = legacyBackupURL
        self.legacyBackupMnemonic = legacyBackupMnemonic
        _kind = State(initialValue: kind)
    }

    private var isLegacyBackupReset: Bool { kind == .legacyBackupReset }
    private var isReset: Bool { kind == .reset || isLegacyBackupReset }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Label(
                        isLegacyBackupReset
                            ? L10n.source("Recover legacy backup with a new identity")
                            : isReset
                                ? L10n.source("Required new-identity security reset")
                                : L10n.source("Required device-authority migration"),
                        systemImage: "exclamationmark.shield"
                    )
                    .font(.title2.weight(.semibold))

                    Text(explanation)
                        .foregroundStyle(isReset ? ThemePalette.danger : ThemePalette.warning)
                        .fixedSize(horizontal: false, vertical: true)

                    if working {
                        ProgressView(
                            mnemonic == nil
                                ? L10n.source("Preparing protected offline authority…")
                                : L10n.source("Publishing the upgraded profile…"))
                    }

                    if let newAddress {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("New account address").font(.caption.weight(.semibold))
                            Text(newAddress)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                        .padding()
                        .background(
                            ThemePalette.surface,
                            in: RoundedRectangle(cornerRadius: 10))
                    }

                    if let mnemonic {
                        Text(isReset
                             ? L10n.source(
                                "These words open the new account authority. The old safety number and device revocations are not preserved.")
                             : L10n.source(
                                "These words open the offline authority for the same account."))
                            .font(.footnote)
                        Text(mnemonic)
                            .font(.body.monospaced())
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                ThemePalette.surface,
                                in: RoundedRectangle(cornerRadius: 10))
                            .textSelection(.enabled)

                        Button {
                            exportingFile = true
                        } label: {
                            Label(
                                saved
                                    ? L10n.source("Save another offline copy…")
                                    : L10n.source("Save offline authority…"),
                                systemImage: "square.and.arrow.down")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(document == nil || working)

                        if isReset {
                            Toggle(
                                "I understand my address and every safety number will change",
                                isOn: $identityChangeConfirmed)
                        }

                        Button(
                            isLegacyBackupReset
                                ? L10n.source("Create new identity and import archive")
                                : L10n.source("Complete security upgrade")
                        ) {
                            complete()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(
                            working || !saved || (isReset && !identityChangeConfirmed))
                    }

                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(ThemePalette.danger)
                    }

                    if !working && mnemonic == nil {
                        if !isReset {
                            Button("I exported or copied a legacy KKR7 backup") {
                                kind = .reset
                                error = nil
                            }
                            .buttonStyle(.bordered)
                        }
                        Button(
                            isLegacyBackupReset
                                ? L10n.source("Prepare fresh recovery authority")
                                : L10n.source("Prepare without changing this profile"),
                            action: prepare)
                            .buttonStyle(.borderedProminent)
                    }
                }
                .padding(24)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            .background(ThemePalette.background)
            .navigationTitle("Security upgrade")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(working)
                }
            }
            .fileExporter(
                isPresented: $exportingFile,
                document: document,
                contentType: .data,
                defaultFilename: isReset
                    ? "komms-new-account-authority.kra"
                    : "komms-account-authority.kra"
            ) { result in
                switch result {
                case .success:
                    saved = true
                    error = nil
                case .failure(let failure):
                    error = errorText(failure)
                }
            }
            .interactiveDismissDisabled(working)
            .onDisappear {
                if !completed { cleanup() }
            }
        }
    }

    private var explanation: String {
        if isLegacyBackupReset {
            return L10n.source(
                "This legacy backup contains an account root that may have been copied, so the former address cannot safely resume. Komms will decrypt it only into an unpublished migration projection, then publish a fresh account containing cleared petnames and accurately labelled local pairwise/note history. Groups, routes, sessions, devices, queues, and service capabilities will not transfer. Every retained contact must be re-verified.")
        }
        if isReset {
            return L10n.source(
                "This Alpha profile copied its account root to another device. Revoking that device cannot erase its copy. The safe upgrade creates a new account, clears live routes, sessions, device/group authority and delivery work, and keeps only clearly marked local pairwise/note history and petnames. Every retained contact must be re-verified.")
        }
        return L10n.source(
            "Komms found no linked-device root copy in this store. Keep this address only if you also never exported or copied a legacy KKR7 backup. If you did, choose the conservative new-identity reset below. In-place migration keeps this device, petnames, and history after you save the root as a separate offline authority.")
    }

    private func prepare() {
        guard !working else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                let directory = FileManager.default.temporaryDirectory
                    .appendingPathComponent(
                        "komms-authority-upgrade-\(UUID().uuidString)",
                        isDirectory: true)
                try FileManager.default.createDirectory(
                    at: directory, withIntermediateDirectories: true)
                let stage = directory.appendingPathComponent("account-authority.kra")
                stagedURL = stage
                if isLegacyBackupReset {
                    let prepared = try await model.prepareLegacyBackupAuthorityReset(
                        recoveryPath: stage)
                    mnemonic = prepared.recoveryMnemonic
                    newAddress = prepared.newAddress
                } else if isReset {
                    let prepared = try await model.prepareAuthorityReset(
                        passphrase: passphrase, recoveryPath: stage)
                    mnemonic = prepared.recoveryMnemonic
                    newAddress = prepared.newAddress
                } else {
                    mnemonic = try await model.prepareAuthorityMigration(
                        passphrase: passphrase, recoveryPath: stage)
                }
                try protectRecoveryAuthority(stage)
                document = RecoveryAuthorityDocument(data: try Data(contentsOf: stage))
            } catch {
                cleanup()
                self.error = errorText(error)
            }
        }
    }

    private func complete() {
        guard let stagedURL, let mnemonic, saved else { return }
        guard !isReset || identityChangeConfirmed else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                if isLegacyBackupReset {
                    guard let legacyBackupURL else {
                        throw CocoaError(.fileNoSuchFile)
                    }
                    let scoped = legacyBackupURL.startAccessingSecurityScopedResource()
                    defer {
                        if scoped { legacyBackupURL.stopAccessingSecurityScopedResource() }
                    }
                    try await model.restore(
                        backup: legacyBackupURL,
                        mnemonic: legacyBackupMnemonic,
                        recoveryAuthority: stagedURL,
                        recoveryMnemonic: mnemonic,
                        passphrase: passphrase)
                } else {
                    try await model.completeAuthorityUpgrade(
                        reset: isReset,
                        passphrase: passphrase,
                        recoveryPath: stagedURL,
                        recoveryMnemonic: mnemonic)
                }
                completed = true
                cleanup()
                dismiss()
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func cleanup() {
        if let stagedURL {
            try? FileManager.default.removeItem(at: stagedURL.deletingLastPathComponent())
        }
        stagedURL = nil
        document = nil
        mnemonic = nil
        newAddress = nil
    }
}

/// Mandatory first-run handoff of the stable account root. The encrypted
/// package is generated into protected transient storage, copied through the
/// system document exporter, and never admitted to ordinary app backup.
struct RecoveryAuthorityView: View {
    @EnvironmentObject private var model: AppModel
    @State private var mnemonic: String?
    @State private var document: RecoveryAuthorityDocument?
    @State private var stagedURL: URL?
    @State private var exportingFile = false
    @State private var saved = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Label(
                        "Save your offline account authority",
                        systemImage: "externaldrive.badge.checkmark"
                    )
                    .font(.title2.weight(.semibold))

                    Text("This step is required before messaging. Anyone holding both this encrypted file and its 24 words can take over your stable identity and revoke every current device. Save the file on offline or removable storage, separate from the words. It is not a routine backup.")
                        .foregroundStyle(ThemePalette.danger)
                        .fixedSize(horizontal: false, vertical: true)

                    if working {
                        ProgressView("Preparing protected offline authority…")
                    }

                    if let mnemonic {
                        Text("Write these 24 words down separately. They are shown once and open only the offline authority file.")
                            .font(.footnote)
                        Text(mnemonic)
                            .font(.body.monospaced())
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                ThemePalette.surface,
                                in: RoundedRectangle(cornerRadius: 10))
                            .textSelection(.enabled)

                        Button {
                            exportingFile = true
                        } label: {
                            Label(
                                saved
                                    ? L10n.source("Save another offline copy…")
                                    : L10n.source("Save offline authority…"),
                                systemImage: "square.and.arrow.down")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(document == nil)

                        Button("I stored both parts separately") {
                            guard saved else {
                                error = L10n.source(
                                    "Save the .kra file before continuing.")
                                return
                            }
                            cleanup()
                            model.completeRecoveryAuthorityOnboarding()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!saved)
                    }

                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(ThemePalette.danger)
                    }

                    if !working && mnemonic == nil {
                        Button("Try preparing the authority again", action: prepare)
                            .buttonStyle(.bordered)
                    }
                }
                .padding(24)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            .background(ThemePalette.background)
            .navigationBarHidden(true)
            .task {
                if mnemonic == nil { prepare() }
            }
            .fileExporter(
                isPresented: $exportingFile,
                document: document,
                contentType: .data,
                defaultFilename: "komms-account-authority.kra"
            ) { result in
                switch result {
                case .success:
                    saved = true
                    error = nil
                case .failure(let failure):
                    error = errorText(failure)
                }
            }
        }
    }

    private func prepare() {
        guard !working else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                let stage: URL
                if let stagedURL {
                    stage = stagedURL
                } else {
                    let directory = FileManager.default.temporaryDirectory
                        .appendingPathComponent(
                            "komms-account-authority-\(UUID().uuidString)",
                            isDirectory: true)
                    try FileManager.default.createDirectory(
                        at: directory, withIntermediateDirectories: true)
                    stage = directory.appendingPathComponent(
                        "komms-account-authority.kra")
                    stagedURL = stage
                    let words = try await model.exportAccountRecoveryAuthority(to: stage)
                    mnemonic = words
                    try protectRecoveryAuthority(stage)
                }
                document = RecoveryAuthorityDocument(data: try Data(contentsOf: stage))
            } catch {
                if mnemonic == nil, let stagedURL {
                    try? FileManager.default.removeItem(
                        at: stagedURL.deletingLastPathComponent())
                    self.stagedURL = nil
                }
                self.error = errorText(error)
            }
        }
    }

    private func cleanup() {
        if let stagedURL {
            try? FileManager.default.removeItem(at: stagedURL.deletingLastPathComponent())
        }
        stagedURL = nil
        document = nil
        mnemonic = nil
    }
}

private struct RecoveryAuthorityDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        self.data = data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

private func protectRecoveryAuthority(_ url: URL) throws {
    try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete],
        ofItemAtPath: url.path)
    var protected = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try protected.setResourceValues(values)
}
