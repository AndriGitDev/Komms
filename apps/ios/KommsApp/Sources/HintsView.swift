// The delivery-hint editor: kind + value rows, the exact shape (and error
// wording) the other shells use. Bad input is rejected here, honestly,
// before anything reaches the node.

import KommsCore
import SwiftUI

struct HintsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let peer: String

    private struct Row: Identifiable {
        let id = UUID()
        var kind = "multiaddr"
        var value = ""
    }

    private static let kinds = ["multiaddr", "relay", "spool", "mesh"]

    @State private var rows: [Row] = []
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach($rows) { $row in
                        VStack {
                            Picker("Kind", selection: $row.kind) {
                                ForEach(Self.kinds, id: \.self) {
                                    Text(kindName($0)).tag($0)
                                }
                            }
                            TextField(
                                row.kind == "mesh"
                                    ? L10n.source("node number or broadcast")
                                    : L10n.source("value"),
                                text: $row.value)
                                .font(.caption.monospaced())
                                .incognitoKeyboard()
                        }
                    }
                    .onDelete { rows.remove(atOffsets: $0) }
                    Button("Add hint") { rows.append(Row()) }
                } footer: {
                    Text("Saving replaces the contact's hint list. Delivery also uses discovery — hints are the paths you already know.")
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }

                Section {
                    Button("Save") { save() }
                }
            }
            .navigationTitle("Delivery hints")
            .toolbar {
                Button("Cancel") { dismiss() }
            }
        }
    }

    private func kindName(_ kind: String) -> String {
        switch kind {
        case "relay": return L10n.text("hint_kind_relay")
        case "spool": return L10n.text("hint_kind_spool")
        case "mesh": return L10n.text("hint_kind_mesh")
        default: return L10n.text("hint_kind_multiaddr")
        }
    }

    private func save() {
        error = nil
        let hints = rows.map { HintSpec($0.kind, $0.value) }
        Task {
            do {
                try await model.setHints(peer: peer, hints: hints)
                dismiss()
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
