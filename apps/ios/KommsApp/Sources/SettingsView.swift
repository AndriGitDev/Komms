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
                        title: "Encrypted backup",
                        detail: "Export identity, contacts, and history",
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
                    Text("Most people never need to change these. Komms chooses safe defaults automatically.")
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
    var body: some View {
        Form {
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
    @State private var serveMailbox = false
    @State private var mdns = true
    @State private var loaded = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Toggle("LAN discovery (mDNS)", isOn: $mdns)
                Toggle("Serve a mailbox for others", isOn: $serveMailbox)
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
            var s = (try? NetworkSettings.load(from: model.dataDir)) ?? NetworkSettings()
            s.listen = Self.lines(listen)
            s.bootstrap = Self.lines(bootstrap)
            let r = relay.trimmingCharacters(in: .whitespaces)
            s.relay = r.isEmpty ? nil : r
            s.mailboxes = Self.lines(mailboxes)
            s.serveMailbox = serveMailbox
            s.mdns = mdns
            try s.save(to: model.dataDir)
            dismiss()
        } catch {
            self.error = errorText(error)
        }
    }
}
