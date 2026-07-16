import KommsCore
import SwiftUI

struct RenameContactView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let contact: Contact

    @State private var name: String
    @State private var pendingAssessment: ContactNameAssessment?
    @State private var error = ""
    @State private var working = false

    init(contact: Contact) {
        self.contact = contact
        _name = State(initialValue: contact.name)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Private local petname") {
                    TextField("Petname", text: $name)
                        .incognitoKeyboard(.words)
                    Text("Stored sealed on this device. It is never sent to the contact and never identifies a recipient.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if !error.isEmpty {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Rename contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Review") { Task { await review() } }
                        .disabled(working)
                }
            }
            .alert(
                "Review name warning",
                isPresented: Binding(
                    get: { pendingAssessment != nil },
                    set: { if !$0 { pendingAssessment = nil } })
            ) {
                Button("Use this name") { Task { await commit(acceptWarnings: true) } }
                Button("Cancel", role: .cancel) { pendingAssessment = nil }
            } message: {
                Text(warningText(pendingAssessment))
            }
        }
    }

    @MainActor private func review() async {
        working = true
        defer { working = false }
        do {
            let assessment = try await model.assessContactName(peer: contact.peer, name: name)
            if assessment.warnings.isEmpty {
                await commit(acceptWarnings: false)
            } else {
                pendingAssessment = assessment
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    @MainActor private func commit(acceptWarnings: Bool) async {
        working = true
        defer { working = false }
        do {
            _ = try await model.renameContact(
                peer: contact.peer, name: name, acceptWarnings: acceptWarnings)
            pendingAssessment = nil
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func warningText(_ assessment: ContactNameAssessment?) -> String {
        guard let assessment else { return "" }
        var lines: [String] = assessment.warnings.map { warning in
            switch warning {
            case .duplicateName:
                "\(assessment.duplicateCount) other contact(s) already use this exact private petname."
            case .confusableName:
                "This name mixes lookalike scripts or resembles another local petname."
            case .bidirectionalControl:
                "This name contains directional controls that can change display order."
            case .invisibleCharacter:
                "This name contains invisible formatting characters."
            }
        }
        lines.append("Store “\(assessment.normalizedName)” anyway? Duplicate names remain separate by peer identity.")
        return lines.joined(separator: "\n\n")
    }
}
