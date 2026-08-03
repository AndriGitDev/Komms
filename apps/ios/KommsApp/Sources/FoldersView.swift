import KommsCore
import SwiftUI
import UIKit

func folderSummary(_ folder: KommsCore.Folder) -> String {
    L10n.text(
        "folder_accessible_summary",
        folder.name,
        Int(clamping: folder.order + 1))
}

struct FolderManagerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @FocusState private var nameFocused: Bool
    @State private var editingId: String?
    @State private var name = ""
    @State private var error: String?
    @State private var deletion: FolderDeletionReview?

    var body: some View {
        NavigationStack {
            Form {
                Section(
                    editingId == nil
                        ? L10n.text("folder_create")
                        : L10n.source("Rename folder")
                ) {
                    TextField("Exact folder name", text: $name)
                        .focused($nameFocused)
                        .incognitoKeyboard()
                        .accessibilityHint("Maximum 256 UTF-8 bytes; exact text is preserved")
                    if let error {
                        Text(error).foregroundStyle(.red)
                            .accessibilityLabel(L10n.text("accessibility_error", error))
                    }
                    HStack {
                        if editingId != nil { Button("Cancel rename", action: cancelEdit) }
                        Spacer()
                        Button(
                            editingId == nil
                                ? L10n.text("folder_create")
                                : L10n.text("folder_save"),
                            action: save)
                    }
                }

                Section("Private folders") {
                    if model.folders.isEmpty { Text("No folders yet.").foregroundStyle(.secondary) }
                    ForEach(Array(model.folders.enumerated()), id: \.element.id) { index, folder in
                        HStack(alignment: .top) {
                            CustomIconAvatar(
                                target: .init(kind: .folder, id: folder.id),
                                label: folder.name)
                            VStack(alignment: .leading) {
                                Text(verbatim: folder.name)
                                    .accessibilityLabel(Text(verbatim: folderSummary(folder)))
                                HStack {
                                    Button("Move up") { reorder(index, index - 1) }
                                        .disabled(index == 0)
                                        .accessibilityLabel(
                                            L10n.text(
                                                "folder_move_up",
                                                folderSummary(folder)))
                                    Button("Move down") { reorder(index, index + 1) }
                                        .disabled(index + 1 == model.folders.count)
                                        .accessibilityLabel(
                                            L10n.text(
                                                "folder_move_down",
                                                folderSummary(folder)))
                                    Spacer()
                                    Button("Rename") { beginEdit(folder) }
                                        .accessibilityLabel(
                                            L10n.text(
                                                "folder_edit_description",
                                                folderSummary(folder)))
                                    Button("Delete", role: .destructive) { previewDelete(folder) }
                                        .accessibilityLabel(
                                            L10n.text(
                                                "folder_delete_description",
                                                folderSummary(folder)))
                                }
                            }
                        }
                    }
                }

                if model.staleFolderRecords.isEmpty == false {
                    Section("Unavailable assignments") {
                        Text("These sealed local rows no longer resolve to both a folder and an available conversation.")
                            .font(.footnote).foregroundStyle(.secondary)
                        ForEach(Array(model.staleFolderRecords.enumerated()), id: \.offset) { _, record in
                            Button(
                                L10n.text(
                                    "folder_stale_cleanup",
                                    folderTargetKindName(record.target)),
                                role: .destructive
                            ) {
                                Task {
                                    do {
                                        try await model.cleanupStaleFolder(id: record.folder, target: record.target)
                                        folderAnnounce(
                                            L10n.text(
                                                "folder_stale_cleaned",
                                                folderTargetKindName(record.target)))
                                    } catch { self.error = errorText(error) }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("Private folders")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog(
                "Delete private folder?",
                isPresented: Binding(
                    get: { deletion != nil },
                    set: { if $0 == false { deletion = nil } }),
                titleVisibility: .visible
            ) {
                if let review = deletion {
                    Button(
                        L10n.text(
                            "folder_delete_unfile",
                            Int(clamping: review.count)),
                        role: .destructive
                    ) {
                        Task {
                            do {
                                let removed = try await model.deleteFolder(id: review.folder.id)
                                folderAnnounce(
                                    L10n.text(
                                        "folder_deleted",
                                        Int(clamping: removed)))
                                cancelEdit()
                            } catch { self.error = errorText(error) }
                        }
                    }
                }
                Button("Cancel", role: .cancel) {
                    folderAnnounce(L10n.text("folder_delete_cancelled"))
                }
            } message: {
                if let review = deletion {
                    Text(
                        L10n.text(
                            "folder_delete_review",
                            folderSummary(review.folder),
                            Int(clamping: review.count)))
                }
            }
        }
    }

    private func save() {
        error = nil
        Task {
            do {
                let saved = if let editingId {
                    try await model.renameFolder(id: editingId, name: name)
                } else {
                    try await model.createFolder(name: name)
                }
                folderAnnounce(
                    L10n.text(
                        editingId == nil ? "folder_created" : "folder_updated",
                        folderSummary(saved)))
                cancelEdit()
                nameFocused = true
            } catch { self.error = errorText(error); nameFocused = true }
        }
    }

    private func beginEdit(_ folder: KommsCore.Folder) {
        editingId = folder.id
        name = folder.name
        nameFocused = true
    }

    private func cancelEdit() { editingId = nil; name = ""; error = nil }

    private func reorder(_ from: Int, _ to: Int) {
        let movedSummary = folderSummary(model.folders[from])
        var ids = model.folders.map(\.id)
        let moved = ids.remove(at: from)
        ids.insert(moved, at: to)
        Task {
            do {
                try await model.reorderFolders(ids: ids)
                folderAnnounce(
                    L10n.text(
                        "folder_reordered",
                        movedSummary,
                        to + 1))
            } catch { self.error = errorText(error) }
        }
    }

    private func previewDelete(_ folder: KommsCore.Folder) {
        Task {
            do {
                deletion = .init(
                    folder: folder,
                    count: try await model.folderDeleteAssignmentCount(id: folder.id))
            } catch { self.error = errorText(error) }
        }
    }
}

private struct FolderDeletionReview: Identifiable {
    let folder: KommsCore.Folder
    let count: UInt64
    var id: String { folder.id }
}

struct FolderAssignmentView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let target: FolderTarget
    let targetName: String
    @State private var selected: String?
    @State private var loaded = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Single folder membership") {
                    Picker("Folder", selection: $selected) {
                        Text("Unfiled").tag(String?.none)
                        ForEach(model.folders, id: \.id) { folder in
                            Text(verbatim: folder.name).tag(Optional(folder.id))
                                .accessibilityLabel(Text(verbatim: folderSummary(folder)))
                        }
                    }
                    .pickerStyle(.inline)
                    .disabled(!loaded)
                    Text("Moving replaces the prior folder assignment; labels remain independent.")
                        .font(.footnote).foregroundStyle(.secondary)
                    if let error { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle(L10n.text("folder_assignment_title", targetName))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Move") { apply() }.disabled(!loaded)
                }
            }
            .task {
                do {
                    selected = try await model.conversationFolder(target: target)?.id
                    loaded = true
                } catch { self.error = errorText(error) }
            }
        }
    }

    private func apply() {
        Task {
            do {
                let final = try await model.setFolder(selected, target: target)
                folderAnnounce(
                    L10n.text(
                        "folder_assignment_result",
                        targetName,
                        final.map(folderSummary) ?? L10n.text("folder_unfiled")))
                dismiss()
            } catch { self.error = errorText(error) }
        }
    }
}

private func folderTargetKindName(_ target: FolderTarget) -> String {
    switch target.kind {
    case .peer: return L10n.text("label_contact_conversation")
    case .group: return L10n.text("label_group_conversation")
    case .noteToSelf: return L10n.text("note_to_self_title")
    }
}

private func folderAnnounce(_ text: String) {
    UIAccessibility.post(notification: .announcement, argument: text)
}
