// Progressive disclosure for everyday and high-threat use. The inbox keeps
// only daily messaging actions; recovery, device, organization, privacy, and
// transport controls live here.

import KommsCore
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var showBackup = false
    @State private var showDevices = false
    @State private var showFolders = false
    @State private var showLabels = false
    @State private var showPins = false
    @State private var showIcons = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Account & devices") {
                    SettingsActionRow(
                        title: "Root-free encrypted backup",
                        detail: "Export identity, contacts, and history; recovery also needs the separate offline authority",
                        systemImage: "externaldrive.badge.timemachine"
                    ) { showBackup = true }
                    SettingsActionRow(
                        title: "Linked devices",
                        detail: "Link, sync, rename, or revoke installations",
                        systemImage: "laptopcomputer.and.iphone"
                    ) { showDevices = true }
                }

                Section("Privacy & appearance") {
                    NavigationLink {
                        PrivacySecurityView()
                    } label: {
                        Label("Privacy and screen security", systemImage: "lock.shield")
                    }
                    Picker("Theme", selection: Binding(
                        get: { model.themePreference },
                        set: { preference in Task { await model.setTheme(preference) } }
                    )) {
                        Text("System").tag(ThemePreference.system)
                        Text("Light").tag(ThemePreference.light)
                        Text("Dark").tag(ThemePreference.dark)
                    }
                }

                Section("Conversation organization") {
                    SettingsActionRow(title: "Folders", systemImage: "folder") {
                        showFolders = true
                    }
                    SettingsActionRow(title: "Labels", systemImage: "tag") {
                        showLabels = true
                    }
                    SettingsActionRow(title: "Pinned conversations", systemImage: "pin") {
                        showPins = true
                    }
                    SettingsActionRow(title: "Private custom icons", systemImage: "person.crop.circle") {
                        showIcons = true
                    }
                }

                Section {
                    NavigationLink {
                        AdvancedNetworkSettingsView()
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Label("Network & transports", systemImage: "network")
                            Text("Relays, bootstrap peers, LAN discovery, and mailbox service")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Advanced")
                } footer: {
                    Text("Optional provider defaults are signed, replaceable, and never required for core messaging routes.")
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                Button("Done") { dismiss() }
            }
            .sheet(isPresented: $showBackup) { BackupView() }
            .sheet(isPresented: $showDevices) { DevicesView() }
            .sheet(isPresented: $showFolders) { FolderManagerView() }
            .sheet(isPresented: $showLabels) { LabelManagerView() }
            .sheet(isPresented: $showPins) { PinsView() }
            .sheet(isPresented: $showIcons) { CustomIconsView() }
        }
        .tint(ThemePalette.accent)
    }
}

private struct SettingsActionRow: View {
    let title: String
    var detail: String? = nil
    let systemImage: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Label {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .foregroundStyle(ThemePalette.textPrimary)
                        if let detail {
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(ThemePalette.textSecondary)
                        }
                    }
                } icon: {
                    Image(systemName: systemImage)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(ThemePalette.textSecondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct PrivacySecurityView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section {
                Picker("Best-effort native wake", selection: Binding(
                    get: { model.nativeWakePreference },
                    set: { preference in
                        Task { await model.setNativeWakePreference(preference) }
                    }
                )) {
                    Text("Off").tag(NativeWakePreference.disabled)
                    Text("Background only").tag(NativeWakePreference.backgroundOnly)
                    Text("Static “New activity” notice").tag(NativeWakePreference.genericVisible)
                }
            } header: {
                Text("Native wake")
            } footer: {
                Text(
                    "Wake carries no sender, conversation, message, unread count, or timestamp and never changes sent or delivered state. "
                    + "iOS may suppress background execution after force-quit, when Background App Refresh is off, or under system limits. "
                    + "Mailbox and direct retry remain authoritative.")
            }

            let screenSecurity = screenSecurityPolicy(platform: .ios)
            Section {
                Text(screenSecurity.mechanism)
                ForEach(screenSecurity.limitations, id: \.self) { limitation in
                    Text("• \(limitation)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Screen security · always on")
            } footer: {
                Text("Komms hides inactive app-switcher snapshots and responds to live-capture notifications. iOS still screenshots cannot be universally blocked.")
            }

            let inputPrivacy = incognitoKeyboardPolicy(platform: .ios)
            Section {
                Text(inputPrivacy.mechanism)
                ForEach(inputPrivacy.limitations, id: \.self) { limitation in
                    Text("• \(limitation)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Input privacy · always on")
            } footer: {
                Text("Passphrases and recovery mnemonics use secure fields. Other fields disable autocorrection, but iOS has no per-field personalized-learning guarantee.")
            }
        }
        .navigationTitle("Privacy & security")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// The same secret-free `settings.json` knobs as kultd and the other shells.
/// Changes made while unlocked take effect after the next lock and unlock.
struct AdvancedNetworkSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var listen = ""
    @State private var bootstrap = ""
    @State private var relay = ""
    @State private var mailboxes = ""
    @State private var mode = "standard"
    @State private var standardDisclosureConfirmed = false
    @State private var sovereignPublishDirectRoutes = false
    @State private var providerDirectory = ""
    @State private var providerRoots = ""
    @State private var rendezvous = ""
    @State private var wake = ""
    @State private var torProxy = ""
    @State private var serveMailbox = false
    @State private var mdns = true
    @State private var loaded = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Picker("Mode", selection: $mode) {
                    Text("Standard").tag("standard")
                    Text("Private").tag("private")
                    Text("Sovereign").tag("sovereign")
                }
                .pickerStyle(.segmented)

                Text(modeDisclosure)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("\(mode.capitalized) mode. \(modeDisclosure)")

                if mode == "standard" {
                    Toggle(
                        "I reviewed the Standard provider disclosure",
                        isOn: $standardDisclosureConfirmed
                    )
                }
                if mode == "sovereign" {
                    Toggle(
                        "Publish direct routes after accepting the reachability warning",
                        isOn: $sovereignPublishDirectRoutes
                    )
                }
            } header: {
                Text("Operating mode")
            }

            Section {
                Toggle("LAN discovery (mDNS)", isOn: $mdns)
                Toggle("Serve a mailbox for others", isOn: $serveMailbox)
            }

            Section("Signed provider directory") {
                TextField("Candidate JSON path (optional)", text: $providerDirectory)
                    .font(.caption.monospaced())
                    .incognitoKeyboard()
                TextEditor(text: $providerRoots)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
                    .accessibilityLabel("Trusted offline directory keys, one per line")
            }

            Section {
                TextEditor(text: $rendezvous)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
                    .accessibilityLabel("Manual rendezvous providers, one per line")
                TextField("Private Tor SOCKS5 endpoint", text: $torProxy)
                    .font(.caption.monospaced())
                    .incognitoKeyboard()
            } header: {
                Text("Optional rendezvous")
            } footer: {
                Text("One per line: https://host,leaf_sha256,standard|private|both. Private access requires an explicit loopback Tor endpoint.")
            }

            Section {
                TextEditor(text: $wake)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
                    .accessibilityLabel("Manual native-wake gateways, one per line")
            } header: {
                Text("Native-wake gateways")
            } footer: {
                Text("Separately keyed from rendezvous. One per line: https://host,leaf_sha256,standard|private|both. Provider tokens go only to the selected gateway.")
            }

            Section("Listen multiaddrs (one per line)") {
                TextEditor(text: $listen)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
            }
            Section("Bootstrap peers (one per line)") {
                TextEditor(text: $bootstrap)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
            }
            Section("Relay (blank = first bootstrap peer)") {
                TextField("/dns4/…/p2p/…", text: $relay)
                    .font(.caption.monospaced())
                    .incognitoKeyboard()
            }
            Section("Mailbox relays (one per line)") {
                TextEditor(text: $mailboxes)
                    .font(.caption.monospaced())
                    .frame(minHeight: 60)
                    .incognitoKeyboard()
            }

            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }

            Section {
                Button("Save network settings") { save() }
            } footer: {
                Text(model.session == nil
                    ? "Saved next to the encrypted store. No secrets are included."
                    : "Changes apply after the next lock and unlock.")
            }
        }
        .navigationTitle("Network & transports")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: load)
    }

    private static func lines(_ s: String) -> [String] {
        s.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        do {
            let s = try NetworkSettings.load(from: model.dataDir)
            mode = s.mode
            standardDisclosureConfirmed = s.standardDisclosureConfirmed
            sovereignPublishDirectRoutes = s.sovereignPublishDirectRoutes
            providerDirectory = s.providerDirectory ?? ""
            providerRoots = s.providerDirectoryRoots.joined(separator: "\n")
            rendezvous = s.rendezvous.map { entry in
                let access = entry.standard && entry.privateViaTor
                    ? "both"
                    : (entry.standard ? "standard" : "private")
                return "\(entry.origin),\(entry.staticKey),\(access)"
            }.joined(separator: "\n")
            wake = s.wake.map { entry in
                let access = entry.standard && entry.privateViaTor
                    ? "both"
                    : (entry.standard ? "standard" : "private")
                return "\(entry.origin),\(entry.staticKey),\(access)"
            }.joined(separator: "\n")
            torProxy = s.torProxy ?? ""
            listen = s.listen.joined(separator: "\n")
            bootstrap = s.bootstrap.joined(separator: "\n")
            relay = s.relay ?? ""
            mailboxes = s.mailboxes.joined(separator: "\n")
            serveMailbox = s.serveMailbox
            mdns = s.mdns
        } catch {
            self.error = errorText(error)
        }
    }

    private func save() {
        error = nil
        do {
            // Keep knobs this screen doesn't edit (radios, spool, bridge).
            let previous =
                (try? NetworkSettings.load(from: model.dataDir)) ?? NetworkSettings()
            var s = previous
            s.mode = mode
            s.standardDisclosureConfirmed = standardDisclosureConfirmed
            s.sovereignPublishDirectRoutes = sovereignPublishDirectRoutes
            let directory = providerDirectory.trimmingCharacters(in: .whitespaces)
            s.providerDirectory = directory.isEmpty ? nil : directory
            s.providerDirectoryRoots = Self.lines(providerRoots)
            s.rendezvous = try parseRendezvous()
            s.wake = try parseWake()
            let proxy = torProxy.trimmingCharacters(in: .whitespaces)
            s.torProxy = proxy.isEmpty ? nil : proxy
            if s.mode == "standard",
               s.providerDirectory != nil,
               !s.standardDisclosureConfirmed {
                throw SettingsError(
                    "Review and confirm the Standard provider disclosure before using a signed provider directory.")
            }
            if s.mode == "private",
               s.torProxy == nil,
               s.providerDirectory != nil
                || s.rendezvous.contains(where: \.privateViaTor)
                || s.wake.contains(where: \.privateViaTor) {
                throw SettingsError(
                    "Private optional providers require an explicit loopback Tor SOCKS5 endpoint.")
            }
            s.listen = Self.lines(listen)
            s.bootstrap = Self.lines(bootstrap)
            let r = relay.trimmingCharacters(in: .whitespaces)
            s.relay = r.isEmpty ? nil : r
            s.mailboxes = Self.lines(mailboxes)
            s.serveMailbox = serveMailbox
            s.mdns = mdns
            let nativeWakeRuntimeChanged =
                s.mode != previous.mode
                || s.providerDirectory != previous.providerDirectory
                || s.providerDirectoryRoots != previous.providerDirectoryRoots
                || s.wake != previous.wake
                || s.torProxy != previous.torProxy
            try s.save(to: model.dataDir)
            if nativeWakeRuntimeChanged {
                Task { await model.nativeWakeNetworkSettingsChanged() }
            }
            dismiss()
        } catch {
            self.error = errorText(error)
        }
    }

    private var modeDisclosure: String {
        switch mode {
        case "private":
            return "Optional rendezvous uses your local Tor proxy. Bootstrap and mailbox operators can still observe their own connections; this mode does not claim provider non-collusion."
        case "sovereign":
            return "Directory defaults and optional rendezvous or wake are disabled. DHT, user-selected mailboxes, direct, LAN, mesh, QR/file, and sneakernet routes remain."
        default:
            return "Disclosed, replaceable providers can observe your network address, timing, and service requests, but not message contents or your contact list."
        }
    }

    private func parseRendezvous() throws -> [RendezvousSetting] {
        try Self.lines(rendezvous).enumerated().map { index, line in
            let parts = line.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 3,
                  parts[0].hasPrefix("https://"),
                  parts[1].count == 64,
                  parts[1].allSatisfy({ $0.isNumber || ("a"..."f").contains(String($0)) })
            else {
                throw SettingsError(
                    "Rendezvous line \(index + 1) must contain an HTTPS origin, 64 lowercase hex characters, and standard, private, or both.")
            }
            let access: (Bool, Bool)
            switch parts[2] {
            case "standard": access = (true, false)
            case "private": access = (false, true)
            case "both": access = (true, true)
            default:
                throw SettingsError(
                    "Rendezvous line \(index + 1) must end in standard, private, or both.")
            }
            return RendezvousSetting(
                origin: parts[0],
                staticKey: parts[1],
                standard: access.0,
                privateViaTor: access.1
            )
        }
    }

    private func parseWake() throws -> [WakeSetting] {
        try Self.lines(wake).enumerated().map { index, line in
            let parts = line.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 3,
                  parts[0].hasPrefix("https://"),
                  parts[1].count == 64,
                  parts[1].allSatisfy({ $0.isNumber || ("a"..."f").contains(String($0)) })
            else {
                throw SettingsError(
                    "Wake-gateway line \(index + 1) must contain an HTTPS origin, 64 lowercase hex characters, and standard, private, or both.")
            }
            let access: (Bool, Bool)
            switch parts[2] {
            case "standard": access = (true, false)
            case "private": access = (false, true)
            case "both": access = (true, true)
            default:
                throw SettingsError(
                    "Wake-gateway line \(index + 1) must end in standard, private, or both.")
            }
            return WakeSetting(
                origin: parts[0],
                staticKey: parts[1],
                standard: access.0,
                privateViaTor: access.1)
        }
    }
}
