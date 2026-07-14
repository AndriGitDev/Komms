// A sender-key group conversation: sender-labelled inbound rows, honest
// per-recipient outbound delivery, and creator-scoped roster controls.

import KommsCore
import SwiftUI

struct GroupChatView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let groupId: String

    @State private var draft = ""
    @State private var error: String?
    @State private var showMembers = false
    @State private var scheduleEditor: ScheduleEditor?

    private var group: KommsCore.Group? { model.groups.first { $0.id == groupId } }
    private var history: [GroupMessage] {
        (model.groupHistories[groupId] ?? []).filter { $0.contentKind != .attachment }
    }
    private var attachments: [Attachment] {
        model.attachments.filter {
            $0.conversation == .group && $0.group == groupId
        }
    }
    private var scheduled: [ScheduledMessage] {
        model.scheduledMessages
            .filter { message in
                if case .group = message.conversation { return message.destination == groupId }
                return false
            }
            .sorted { $0.notBefore < $1.notBefore }
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(history, id: \.id) { message in
                            GroupMessageBubble(message: message, memberName: memberName)
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
                AttachmentPickerButton(
                    destination: .group(groupId),
                    disabled: group == nil
                ) { error in
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
                .disabled(
                    group == nil
                        || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityLabel("Schedule message")
                Button {
                    send()
                } label: {
                    Image(systemName: "arrow.up.circle.fill").font(.title2)
                }
                .disabled(
                    group == nil
                        || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
        .navigationTitle(group?.name ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Members") { showMembers = true }
                    .disabled(group == nil)
            }
        }
        .sheet(isPresented: $showMembers) { GroupMembersView(groupId: groupId) }
        .sheet(item: $scheduleEditor) { editor in
            ScheduledMessageEditor(
                editor: editor,
                save: { body, date in
                    if let message = editor.message {
                        try await model.editScheduled(
                            message: message.id, body: body, notBefore: date)
                    } else {
                        try await model.scheduleGroup(
                            group: groupId, body: body, notBefore: date)
                        draft = ""
                    }
                })
        }
        .task {
            do {
                try await model.followGroup(group: groupId)
            } catch {
                self.error = errorText(error)
            }
        }
        .onChange(of: group?.id) { id in
            if id == nil { dismiss() }
        }
    }

    private func memberName(_ peer: String) -> String {
        if peer == model.status?.peer { return "You" }
        return model.contacts.first(where: { $0.peer == peer })?.name
            ?? String(peer.prefix(12)) + "…"
    }

    private func send() {
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        draft = ""
        error = nil
        Task {
            do {
                try await model.sendGroup(group: groupId, body: body)
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

private struct GroupMessageBubble: View {
    let message: GroupMessage
    let memberName: (String) -> String

    private var outbound: Bool { message.direction == .outbound }

    var body: some View {
        HStack {
            if outbound { Spacer(minLength: 40) }
            VStack(alignment: outbound ? .trailing : .leading, spacing: 3) {
                if !outbound {
                    Text(memberName(message.sender))
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                }
                Text(message.body)
                    .padding(10)
                    .background(
                        outbound ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15),
                        in: RoundedRectangle(cornerRadius: 12))
                Text(Date(timeIntervalSince1970: TimeInterval(message.timestamp)), style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if outbound {
                    ForEach(message.deliveries, id: \.peer) { delivery in
                        Text("\(memberName(delivery.peer)) · \(stateText(delivery.state))")
                            .font(.caption2)
                            .foregroundStyle(
                                delivery.state == .delivered ? .green : .secondary)
                    }
                }
            }
            if !outbound { Spacer(minLength: 40) }
        }
    }

    private func stateText(_ state: DeliveryState) -> String {
        switch state {
        case .queued: return "queued"
        case .sent: return "sent"
        case .delivered: return "delivered"
        case .received: return "received"
        }
    }
}

private struct GroupMembersView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let groupId: String

    @State private var removalPeer: String?
    @State private var showLeave = false
    @State private var working = false
    @State private var error: String?

    private var group: KommsCore.Group? { model.groups.first { $0.id == groupId } }
    private var ownPeer: String? { model.status?.peer }
    private var isCreator: Bool { group?.creator == ownPeer }
    private var candidates: [Contact] {
        guard let group else { return [] }
        return model.contacts
            .filter { !group.members.contains($0.peer) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    var body: some View {
        NavigationStack {
            List {
                if let group {
                    Section {
                        Text(summary(group))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Section("Members") {
                        ForEach(group.members, id: \.self) { peer in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(memberName(peer))
                                    Text(peer == group.creator ? "creator" : "member")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if isCreator && peer != ownPeer {
                                    Button("Remove", role: .destructive) {
                                        removalPeer = peer
                                    }
                                    .disabled(working)
                                }
                            }
                        }
                    }

                    if isCreator && !candidates.isEmpty {
                        Section {
                            Menu("Add member") {
                                ForEach(candidates, id: \.peer) { contact in
                                    Button(contact.name) { add(contact) }
                                }
                            }
                            .disabled(working)
                        }
                    }

                    Section {
                        Button("Leave group", role: .destructive) { showLeave = true }
                            .disabled(working)
                    } footer: {
                        Text("Message history stays stored on this device after leaving.")
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle(group.map { "Members of \($0.name)" } ?? "Members")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert(
                "Remove member?",
                isPresented: Binding(
                    get: { removalPeer != nil },
                    set: { if !$0 { removalPeer = nil } })
            ) {
                Button("Remove", role: .destructive) { removeSelected() }
                Button("Cancel", role: .cancel) { removalPeer = nil }
            } message: {
                Text(
                    "Remove \(memberName(removalPeer ?? ""))? "
                        + "Group keys rotate immediately for everyone who remains.")
            }
            .confirmationDialog(
                "Leave \(group?.name ?? "group")?",
                isPresented: $showLeave,
                titleVisibility: .visible
            ) {
                Button("Leave group", role: .destructive) { leave() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Message history stays stored on this device.")
            }
        }
    }

    private func memberName(_ peer: String) -> String {
        if peer == ownPeer { return "You" }
        return model.contacts.first(where: { $0.peer == peer })?.name
            ?? String(peer.prefix(12)) + "…"
    }

    private func summary(_ group: KommsCore.Group) -> String {
        let count = "\(group.members.count) "
            + (group.members.count == 1 ? "member" : "members")
        return isCreator
            ? "\(count) · You manage this group."
            : "\(count) · \(memberName(group.creator)) manages this group."
    }

    private func add(_ contact: Contact) {
        working = true
        error = nil
        Task {
            do {
                try await model.addGroupMember(group: groupId, peer: contact.peer)
            } catch {
                self.error = errorText(error)
            }
            working = false
        }
    }

    private func removeSelected() {
        guard let peer = removalPeer else { return }
        removalPeer = nil
        working = true
        error = nil
        Task {
            do {
                try await model.removeGroupMember(group: groupId, peer: peer)
            } catch {
                self.error = errorText(error)
            }
            working = false
        }
    }

    private func leave() {
        working = true
        error = nil
        Task {
            do {
                try await model.leaveGroup(group: groupId)
                dismiss()
            } catch {
                self.error = errorText(error)
                working = false
            }
        }
    }
}
