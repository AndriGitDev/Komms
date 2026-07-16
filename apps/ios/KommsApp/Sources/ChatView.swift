// One conversation: history bubbles with the node's honest delivery ladder
// (`queued` → `sent` → `delivered`, plus the mesh "held" verdict as a
// notice), a composer, and doors to verification and the hint editor.

import KommsCore
import SwiftUI

struct ChatView: View {
    @EnvironmentObject private var model: AppModel
    let peer: String

    @State private var draft = ""
    @State private var error: String?
    @State private var showVerify = false
    @State private var showHints = false
    @State private var showFolder = false
    @State private var showLabels = false
    @State private var scheduleEditor: ScheduleEditor?
    @State private var messageEditor: MessageEditDraft?
    @State private var ephemeralLifetime: EphemeralLifetime?

    private var contact: Contact? {
        model.contacts.first { $0.peer == peer }
    }

    private var history: [Message] {
        (model.histories[peer] ?? []).filter {
            $0.contentKind != .attachment && $0.contentKind != .viewOnceAttachment
        }
    }
    private var attachments: [Attachment] {
        model.attachments.filter {
            $0.conversation == .pairwise && $0.peer == peer
        }
    }
    private var scheduled: [ScheduledMessage] {
        model.scheduledMessages
            .filter { message in
                if case .peer = message.conversation { return message.destination == peer }
                return false
            }
            .sorted { $0.notBefore < $1.notBefore }
    }

    var body: some View {
        VStack(spacing: 0) {
            LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .peer, id: peer)))
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(history, id: \.id) { message in
                            MessageBubble(
                                message: message,
                                edit: {
                                    messageEditor = MessageEditDraft(
                                        contentId: message.id, body: message.body)
                                })
                                .id(message.id)
                        }
                        ForEach(scheduled, id: \.id) { message in
                            ScheduledMessageBubble(
                                message: message,
                                edit: { scheduleEditor = ScheduleEditor(message: message) },
                                cancel: { cancel(message) })
                                .id(message.id)
                        }
                        ForEach(attachments, id: \.transferId) { attachment in
                            AttachmentTransferView(attachment: attachment)
                                .id("attachment-\(attachment.transferId)")
                        }
                    }
                    .padding()
                }
                .onChange(of: history.count + scheduled.count + attachments.count) { _ in
                    if let attachment = attachments.last {
                        proxy.scrollTo("attachment-\(attachment.transferId)", anchor: .bottom)
                    } else if let last = scheduled.last?.id ?? history.last?.id {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }

            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }

            EphemeralTextControl(lifetime: $ephemeralLifetime)
                .padding(.horizontal)
            HStack {
                AttachmentPickerButton(destination: .peer(peer)) { error in
                    self.error = error
                }
                AudioComposerButton(destination: .peer(peer)) { error in
                    self.error = error
                }
                TextField("Message", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1...4)
                    .incognitoKeyboard(capitalization: .sentences)
                Button {
                    scheduleEditor = ScheduleEditor(body: draft)
                } label: {
                    Image(systemName: "calendar.badge.clock").font(.title2)
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityLabel("Schedule message")
                Button {
                    send()
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .navigationTitle(contact?.name ?? String(peer.prefix(12)))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if contact?.verified == true {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                }
                Menu {
                    Button("Verify safety number") { showVerify = true }
                    Button("Delivery hints") { showHints = true }
                    Button("Move to folder") { showFolder = true }
                    Button("Labels") { showLabels = true }
                    Button(model.isPinned(PinTarget(kind: .peer, id: peer)) ? "Unpin" : "Pin") {
                        model.togglePin(PinTarget(kind: .peer, id: peer))
                    }
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
            }
        }
        .sheet(isPresented: $showVerify) { VerifyView(peer: peer) }
        .sheet(isPresented: $showHints) { HintsView(peer: peer) }
        .sheet(isPresented: $showFolder) {
            FolderAssignmentView(
                target: FolderTarget(kind: .peer, id: peer),
                targetName: contact?.name ?? "Contact")
        }
        .sheet(isPresented: $showLabels) {
            LabelAssignmentView(
                target: LabelTarget(kind: .peer, id: peer),
                targetName: contact?.name ?? "Contact")
        }
        .sheet(item: $scheduleEditor) { editor in
            ScheduledMessageEditor(
                editor: editor,
                save: { body, date in
                    if let message = editor.message {
                        try await model.editScheduled(
                            message: message.id, body: body, notBefore: date)
                    } else {
                        try await model.schedule(peer: peer, body: body, notBefore: date)
                        draft = ""
                    }
                })
        }
        .sheet(item: $messageEditor) { editor in
            MessageEditEditor(editor: editor) { replacement in
                try await model.editMessage(
                    peer: peer, targetContentId: editor.contentId, text: replacement)
            }
        }
        .task {
            do {
                try await model.follow(peer: peer)
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func send() {
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        draft = ""
        error = nil
        Task {
            do {
                if let lifetime = ephemeralLifetime {
                    try await model.sendDisappearing(
                        peer: peer, body: body, lifetimeSeconds: lifetime.rawValue)
                } else {
                    try await model.send(peer: peer, body: body)
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func cancel(_ message: ScheduledMessage) {
        Task {
            do {
                try await model.cancelScheduled(message: message.id)
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

private struct MessageBubble: View {
    @EnvironmentObject private var model: AppModel
    let message: Message
    let edit: () -> Void

    private var outbound: Bool { message.direction == .outbound }

    /// The delivery ladder, verbatim: only `delivered` means an end-to-end
    /// encrypted receipt came back.
    private var stateText: String {
        switch message.state {
        case .queued: return "queued"
        case .sent: return "sent"
        case .delivered: return "delivered"
        case .received: return ""
        }
    }

    var body: some View {
        HStack {
            if outbound { Spacer(minLength: 40) }
            VStack(alignment: outbound ? .trailing : .leading, spacing: 2) {
                FormattedTextView(formatted: model.formattedText(source: message.body))
                    .padding(10)
                    .background(
                        outbound ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15),
                        in: RoundedRectangle(cornerRadius: 12))
                if outbound {
                    HStack(spacing: 4) {
                        Text(stateText)
                            .foregroundStyle(
                                message.state == .delivered ? .green : .secondary)
                        if message.edited {
                            Text("· edited r\(message.editRevision)")
                                .foregroundStyle(.secondary)
                        }
                        if message.contentKind == .text {
                            Button("Edit", action: edit)
                                .accessibilityLabel("Edit this message")
                        }
                    }
                    .font(.caption2)
                } else if message.edited {
                    Text("edited r\(message.editRevision)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if message.contentKind == .disappearingText, let expiresAt = message.expiresAt {
                    Text("Removes \(Date(timeIntervalSince1970: TimeInterval(expiresAt)), style: .relative)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHint("Removed locally; other devices may retain copies")
                }
                if message.edited {
                    EditVersionHistoryView(versions: message.versions)
                }
            }
            if !outbound { Spacer(minLength: 40) }
        }
    }
}

struct MessageEditDraft: Identifiable {
    let id = UUID()
    let contentId: String
    let body: String
}

struct MessageEditEditor: View {
    @Environment(\.dismiss) private var dismiss
    let editor: MessageEditDraft
    let save: (String) async throws -> Void

    @State private var text: String
    @State private var error: String?
    @State private var working = false

    init(editor: MessageEditDraft, save: @escaping (String) async throws -> Void) {
        self.editor = editor
        self.save = save
        _text = State(initialValue: editor.body)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $text)
                        .frame(minHeight: 140)
                        .incognitoKeyboard(capitalization: .sentences)
                } footer: {
                    Text("Saving creates a new authenticated edit event. The original and prior versions remain in this conversation.")
                }
                if let error {
                    Text(error).foregroundStyle(.red)
                }
            }
            .navigationTitle("Edit message")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        working = true
                        error = nil
                        Task {
                            do {
                                try await save(text)
                                dismiss()
                            } catch {
                                self.error = errorText(error)
                                working = false
                            }
                        }
                    }
                    .disabled(text.isEmpty || working)
                }
            }
        }
    }
}

struct EditVersionHistoryView: View {
    let versions: [EditVersion]

    var body: some View {
        DisclosureGroup("Version history (\(versions.count))") {
            ForEach(Array(versions.reversed().enumerated()), id: \.offset) { _, version in
                VStack(alignment: .leading, spacing: 2) {
                    Text(version.revision == 0 ? "Original" : "Revision \(version.revision)")
                        .font(.caption.bold())
                    Text(Date(timeIntervalSince1970: TimeInterval(version.timestamp)), style: .time)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(version.body)
                        .font(.caption)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 2)
            }
        }
        .font(.caption)
    }
}
