// Create a sender-key group from stored contacts. The node validates the
// roster and remains the only source of protocol state.

import KommsCore
import SwiftUI

struct CreateGroupView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let onCreated: (String) -> Void

    @State private var name = ""
    @State private var selected = Set<String>()
    @State private var working = false
    @State private var error: String?

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !selected.isEmpty && !working
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Group") {
                    TextField("Group name", text: $name)
                        .incognitoKeyboard(capitalization: .words)
                }

                Section("Members") {
                    if model.contacts.isEmpty {
                        Text("Add at least one contact before creating a group.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.contacts.sorted(by: nameBefore), id: \.peer) { contact in
                        Button {
                            if selected.contains(contact.peer) {
                                selected.remove(contact.peer)
                            } else {
                                selected.insert(contact.peer)
                            }
                        } label: {
                            HStack {
                                Text(contact.name).foregroundStyle(.primary)
                                Spacer()
                                if selected.contains(contact.peer) {
                                    Image(systemName: "checkmark.circle.fill")
                                }
                            }
                        }
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("New group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") { create() }
                        .disabled(!canCreate)
                }
            }
        }
    }

    private func nameBefore(_ lhs: Contact, _ rhs: Contact) -> Bool {
        lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
    }

    private func create() {
        let groupName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let members = model.contacts.filter { selected.contains($0.peer) }.map(\.peer)
        working = true
        error = nil
        Task {
            do {
                let group = try await model.createGroup(name: groupName, members: members)
                onCreated(group)
            } catch {
                self.error = errorText(error)
                working = false
            }
        }
    }
}
