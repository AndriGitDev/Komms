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

    private var contact: Contact? {
        model.contacts.first { $0.peer == peer }
    }

    private var history: [Message] {
        (model.histories[peer] ?? []).filter { $0.contentKind != .attachment }
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
                            MessageBubble(message: message)
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
                try await model.send(peer: peer, body: body)
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
    let message: Message

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
                Text(message.body)
                    .padding(10)
                    .background(
                        outbound ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15),
                        in: RoundedRectangle(cornerRadius: 12))
                if outbound {
                    Text(stateText)
                        .font(.caption2)
                        .foregroundStyle(
                            message.state == .delivered ? .green : .secondary)
                }
            }
            if !outbound { Spacer(minLength: 40) }
        }
    }
}
