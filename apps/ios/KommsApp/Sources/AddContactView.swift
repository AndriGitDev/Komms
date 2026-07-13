// Pairing: scan a friend's bundle QR with the camera, paste the hex, or add
// from their kult address alone (DHT lookup). Interoperable with the desktop
// and Android apps and `kult bundle` / `kult add`.

import KommsCore
import SwiftUI

struct AddContactView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    private enum Source: String, CaseIterable {
        case scan = "Scan QR"
        case paste = "Paste hex"
        case address = "Address"
    }

    @State private var source: Source = .scan
    @State private var name = ""
    @State private var bundleHex = ""
    @State private var address = ""
    @State private var multiaddr = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    TextField("Their name", text: $name)
                }

                Picker("Source", selection: $source) {
                    ForEach(Source.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)

                switch source {
                case .scan:
                    Section("Scan their pairing QR") {
                        QrScannerView { scanned in
                            bundleHex = scanned
                            source = .paste
                        }
                        .frame(height: 260)
                    }
                case .paste:
                    Section("Prekey bundle hex") {
                        TextField("Bundle hex", text: $bundleHex, axis: .vertical)
                            .lineLimit(4...8)
                            .font(.caption.monospaced())
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                    Section {
                        TextField("Optional multiaddr hint", text: $multiaddr)
                            .font(.caption.monospaced())
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    } footer: {
                        Text("Where to reach them directly, if you know it — e.g. a LAN or public address. Otherwise discovery finds a path.")
                    }
                case .address:
                    Section {
                        TextField("kk1…", text: $address)
                            .font(.caption.monospaced())
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    } header: {
                        Text("kult address")
                    } footer: {
                        Text("Looks their prekey bundle up on the DHT — needs a working discovery path (bootstrap or LAN).")
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }

                Section {
                    Button(action: add) {
                        if working { ProgressView() } else { Text("Add contact") }
                    }
                    .disabled(working || name.isEmpty || !ready)
                }
            }
            .navigationTitle("Add contact")
            .toolbar {
                Button("Cancel") { dismiss() }
            }
        }
    }

    private var ready: Bool {
        switch source {
        case .scan: return false // scanning hands off to .paste
        case .paste: return !bundleHex.isEmpty
        case .address: return !address.isEmpty
        }
    }

    private func add() {
        error = nil
        working = true
        Task {
            defer { working = false }
            do {
                switch source {
                case .scan:
                    break
                case .paste:
                    let hint = multiaddr.trimmingCharacters(in: .whitespacesAndNewlines)
                    let hints = hint.isEmpty ? [] : [HintSpec("multiaddr", hint)]
                    try await model.addContact(name: name, bundleHex: bundleHex, hints: hints)
                    dismiss()
                case .address:
                    try await model.addContact(name: name, address: address)
                    dismiss()
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
