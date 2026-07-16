import KommsCore
import SwiftUI
import UIKit

let canonicalLabelColors = [
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
]

func labelColorName(_ token: String) -> String {
    switch token {
    case "red": return String(localized: "Red")
    case "orange": return String(localized: "Orange")
    case "yellow": return String(localized: "Yellow")
    case "green": return String(localized: "Green")
    case "teal": return String(localized: "Teal")
    case "blue": return String(localized: "Blue")
    case "purple": return String(localized: "Purple")
    case "pink": return String(localized: "Pink")
    default: return String(localized: "Neutral")
    }
}

func labelSummary(_ label: KommsCore.Label) -> String {
    "\(label.name) — \(labelColorName(label.color)), label \(label.order + 1)"
}

private func labelDisplayColor(_ token: String, scheme: ColorScheme) -> Color {
    switch token {
    case "red": return scheme == .dark ? Color(red: 1, green: 0.54, blue: 0.49) : .red
    case "orange": return scheme == .dark ? Color(red: 1, green: 0.68, blue: 0.4) : .orange
    case "yellow": return scheme == .dark ? Color(red: 0.9, green: 0.8, blue: 0.38) : Color(red: 0.42, green: 0.34, blue: 0)
    case "green": return scheme == .dark ? Color(red: 0.48, green: 0.8, blue: 0.53) : .green
    case "teal": return scheme == .dark ? Color(red: 0.33, green: 0.8, blue: 0.74) : .teal
    case "blue": return scheme == .dark ? Color(red: 0.47, green: 0.68, blue: 0.97) : .blue
    case "purple": return scheme == .dark ? Color(red: 0.71, green: 0.6, blue: 0.98) : .purple
    case "pink": return scheme == .dark ? Color(red: 0.95, green: 0.58, blue: 0.77) : .pink
    default: return .secondary
    }
}

struct LabelChip: View {
    let label: KommsCore.Label
    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "tag.fill")
            Text(verbatim: label.name).lineLimit(1)
            Text(verbatim: labelColorName(label.color)).font(.caption2)
        }
        .font(.caption)
        .padding(.horizontal, 7).padding(.vertical, 4)
        .foregroundStyle(labelDisplayColor(label.color, scheme: scheme))
        .background(.background, in: Capsule())
        .overlay(Capsule().stroke(lineWidth: contrast == .increased ? 2 : 1))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: labelSummary(label)))
    }
}

struct LabelBadgeRow: View {
    let labels: [KommsCore.Label]

    var body: some View {
        if labels.isEmpty == false {
            ScrollView(.horizontal) {
                HStack { ForEach(labels, id: \.id) { LabelChip(label: $0) } }
                    .padding(.horizontal)
            }
            .scrollIndicators(.visible)
            .accessibilityLabel("Private conversation labels")
        }
    }
}

struct LabelManagerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @FocusState private var nameFocused: Bool
    @State private var editingId: String?
    @State private var name = ""
    @State private var color = "neutral"
    @State private var error: String?
    @State private var deletion: LabelDeletionReview?

    var body: some View {
        NavigationStack {
            Form {
                Section(editingId == nil ? "Create label" : "Edit label") {
                    TextField("Exact label name", text: $name)
                        .focused($nameFocused)
                        .incognitoKeyboard()
                        .accessibilityHint("Maximum 256 UTF-8 bytes; exact text is preserved")
                    Picker("Color", selection: $color) {
                        ForEach(canonicalLabelColors, id: \.self) { token in
                            Text(verbatim: labelColorName(token)).tag(token)
                        }
                    }
                    if let error { Text(error).foregroundStyle(.red).accessibilityLabel("Error: \(error)") }
                    HStack {
                        if editingId != nil { Button("Cancel edit", action: cancelEdit) }
                        Spacer()
                        Button(editingId == nil ? "Create" : "Save", action: save)
                    }
                }
                Section("Private labels") {
                    if model.labels.isEmpty { Text("No labels yet.").foregroundStyle(.secondary) }
                    ForEach(model.labels, id: \.id) { label in
                        HStack {
                            LabelChip(label: label)
                            Spacer()
                            Button("Edit") { beginEdit(label) }
                                .accessibilityLabel("Edit \(labelSummary(label))")
                            Button("Delete", role: .destructive) { previewDelete(label) }
                                .accessibilityLabel("Delete \(labelSummary(label))")
                        }
                    }
                }
                if model.staleLabelRecords.isEmpty == false {
                    Section("Unavailable memberships") {
                        Text("These sealed local rows no longer resolve to both a label and an available conversation.")
                            .font(.footnote).foregroundStyle(.secondary)
                        ForEach(Array(model.staleLabelRecords.enumerated()), id: \.offset) { _, record in
                            Button("Clean up unavailable \(targetKindName(record.target)) membership", role: .destructive) {
                                Task {
                                    do {
                                        try await model.cleanupStaleLabel(id: record.label, target: record.target)
                                        announce("Unavailable membership removed.")
                                    } catch { self.error = errorText(error) }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Private labels")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog(
                "Delete private label?",
                isPresented: Binding(
                    get: { deletion != nil },
                    set: { if $0 == false { deletion = nil } }),
                titleVisibility: .visible
            ) {
                if let review = deletion {
                    Button("Delete label and \(review.count) assignments", role: .destructive) {
                        Task {
                            do {
                                let removed = try await model.deleteLabel(id: review.label.id)
                                announce("Label deleted with \(removed) assignments removed.")
                                cancelEdit()
                            } catch { self.error = errorText(error) }
                        }
                    }
                }
                Button("Cancel", role: .cancel) { announce("Label deletion cancelled.") }
            } message: {
                if let review = deletion {
                    Text(verbatim: "Delete \(labelSummary(review.label))? Review the atomic membership removal before continuing.")
                }
            }
        }
    }

    private func save() {
        error = nil
        Task {
            do {
                let saved = if let editingId {
                    try await model.updateLabel(id: editingId, name: name, color: color)
                } else {
                    try await model.createLabel(name: name, color: color)
                }
                announce("\(editingId == nil ? "Created" : "Updated") \(labelSummary(saved)).")
                cancelEdit()
                nameFocused = true
            } catch { self.error = errorText(error); nameFocused = true }
        }
    }

    private func beginEdit(_ label: KommsCore.Label) {
        editingId = label.id; name = label.name; color = canonicalLabelColors.contains(label.color) ? label.color : "neutral"
        nameFocused = true
    }

    private func cancelEdit() { editingId = nil; name = ""; color = "neutral"; error = nil }

    private func previewDelete(_ label: KommsCore.Label) {
        Task {
            do { deletion = .init(label: label, count: try await model.labelDeleteAssignmentCount(id: label.id)) }
            catch { self.error = errorText(error) }
        }
    }
}

private struct LabelDeletionReview: Identifiable {
    let label: KommsCore.Label
    let count: UInt64
    var id: String { label.id }
}

struct LabelAssignmentView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let target: LabelTarget
    let targetName: String
    @State private var assigned: Set<String> = []
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Membership") {
                    if model.labels.isEmpty { Text("No labels exist. Create one in Manage labels first.") }
                    ForEach(model.labels, id: \.id) { label in
                        Toggle(isOn: Binding(
                            get: { assigned.contains(label.id) },
                            set: { update(label, assigned: $0) })) {
                            LabelChip(label: label)
                        }
                        .accessibilityHint("Applies to exactly \(targetName)")
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Labels for \(targetName)")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .onAppear { assigned = Set(model.labelsForTarget(target).map(\.id)) }
        }
    }

    private func update(_ label: KommsCore.Label, assigned requested: Bool) {
        Task {
            do {
                let final = try await model.setLabel(label.id, assigned: requested, target: target)
                assigned = Set(final.map(\.id))
                let result = assigned.contains(label.id) ? "applied" : "removed"
                announce("\(labelSummary(label)) is now \(result) for \(targetName). Final membership: \(final.count) labels.")
            } catch { self.error = errorText(error); assigned = Set(model.labelsForTarget(target).map(\.id)) }
        }
    }
}

private func targetKindName(_ target: LabelTarget) -> String {
    switch target.kind { case .peer: return "contact conversation"; case .group: return "group conversation"; case .noteToSelf: return "note-to-self" }
}

private func announce(_ text: String) {
    UIAccessibility.post(notification: .announcement, argument: text)
}
