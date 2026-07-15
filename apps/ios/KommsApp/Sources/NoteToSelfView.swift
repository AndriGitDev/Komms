// The reserved sealed local conversation. Notes deliberately have no
// transport direction, queue state, or delivery caption.

import KommsCore
import SwiftUI

struct NoteToSelfView: View {
    @EnvironmentObject private var model: AppModel
    let conversationId: String

    @State private var draft = ""
    @State private var error: String?
    @State private var showFolder = false
    @State private var showLabels = false

    var body: some View {
        VStack(spacing: 0) {
            LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .noteToSelf, id: nil)))
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(model.noteHistory, id: \.id) { message in
                            HStack {
                                Spacer(minLength: 40)
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text(message.body)
                                        .padding(10)
                                        .background(
                                            Color.accentColor.opacity(0.2),
                                            in: RoundedRectangle(cornerRadius: 12))
                                    Text("local only")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .id(message.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: model.noteHistory.count) { _ in
                    if let last = model.noteHistory.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }

            if let error {
                Text(error).font(.footnote).foregroundStyle(.red).padding(.horizontal)
            }

            HStack {
                TextField("Note", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1...4)
                Button { send() } label: {
                    Image(systemName: "arrow.up.circle.fill").font(.title2)
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .navigationTitle("Note to self")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button("Folder") { showFolder = true }
                Button("Labels") { showLabels = true }
            }
        }
        .sheet(isPresented: $showFolder) {
            FolderAssignmentView(
                target: FolderTarget(kind: .noteToSelf, id: nil),
                targetName: "Note to self")
        }
        .sheet(isPresented: $showLabels) {
            LabelAssignmentView(
                target: LabelTarget(kind: .noteToSelf, id: nil),
                targetName: "Note to self")
        }
        .task {
            if conversationId != model.noteToSelfId() {
                error = "Unknown local conversation"
            } else {
                await model.refresh()
            }
        }
    }

    private func send() {
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        draft = ""
        error = nil
        Task {
            do {
                try await model.sendNoteToSelf(body: body)
            } catch {
                self.error = errorText(error)
            }
        }
    }
}
