// Network settings: the same secret-free `settings.json` (and knobs) as
// `kultd`'s flags and the desktop/Android apps. Applied when the node
// starts — edits while unlocked take effect on the next unlock.

import KommsCore
import SwiftUI

struct SettingsView: View {
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
        NavigationStack {
            Form {
                Section {
                    Toggle("LAN discovery (mDNS)", isOn: $mdns)
                    Toggle("Serve a mailbox for others", isOn: $serveMailbox)
                }

                Section("Listen multiaddrs (one per line)") {
                    TextEditor(text: $listen)
                        .font(.caption.monospaced())
                        .frame(minHeight: 60)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                Section("Bootstrap peers (one per line)") {
                    TextEditor(text: $bootstrap)
                        .font(.caption.monospaced())
                        .frame(minHeight: 60)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                Section("Relay (blank = first bootstrap peer)") {
                    TextField("/dns4/…/p2p/…", text: $relay)
                        .font(.caption.monospaced())
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                Section("Mailbox relays (one per line)") {
                    TextEditor(text: $mailboxes)
                        .font(.caption.monospaced())
                        .frame(minHeight: 60)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }

                Section {
                    Button("Save") { save() }
                } footer: {
                    Text(model.session == nil
                        ? "Saved to settings.json next to the store — no secrets."
                        : "Saved to settings.json — applies on the next unlock.")
                }
            }
            .navigationTitle("Network settings")
            .toolbar {
                Button("Cancel") { dismiss() }
            }
            .onAppear(perform: load)
        }
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
