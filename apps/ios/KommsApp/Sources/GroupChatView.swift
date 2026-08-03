// A sender-key group conversation: sender-labelled inbound rows, honest
// per-recipient outbound delivery, and creator-scoped roster controls.

import KommsCore
import SwiftUI
import UIKit

struct GroupChatView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    let groupId: String

    @State private var draft = ""
    @State private var error: String?
    @State private var showMembers = false
    @State private var scheduleEditor: ScheduleEditor?
    @State private var draftMentions: [MentionDraftSpan] = []
    @State private var mentionCapability: GroupMentionCapability?
    @State private var mentionInsertion: MentionInsertion?
    @State private var mentionStatus = L10n.text("mention_member_description")
    @State private var showMentionPicker = false
    @State private var showPlainFallback = false
    @State private var showFolder = false
    @State private var showLabels = false
    @State private var showCreatePoll = false
    @State private var messageEditor: MessageEditDraft?
    @State private var ephemeralLifetime: EphemeralLifetime?

    private var group: KommsCore.Group? { model.groups.first { $0.id == groupId } }
    private var history: [GroupMessage] {
        (model.groupHistories[groupId] ?? []).filter {
            $0.contentKind != .attachment && $0.contentKind != .viewOnceAttachment
        }
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
    private var polls: [GroupPoll] { model.groupPolls[groupId] ?? [] }
    private var authority: GroupAuthority? { model.groupAuthorities[groupId] }
    private var security: GroupSecurity? { model.groupSecurities[groupId] }
    private var securityReady: Bool { security?.level == .recipientAuthenticated }

    var body: some View {
        presentedContent
            .task {
                do {
                    try await model.followGroup(group: groupId)
                    let saved = MentionDraftStore.load(group: groupId)
                    draft = saved.text
                    draftMentions = saved.spans
                } catch {
                    self.error = errorText(error)
                }
            }
            .onChange(of: group?.id) { id in
                if id == nil { dismiss() }
            }
            .onChange(of: draft) { _ in persistDraft() }
            .onChange(of: draftMentions) { _ in persistDraft() }
            .onChange(of: group?.members ?? []) { _ in revalidateMentionReview() }
            .onChange(of: model.notices.count) { _ in revalidateMentionReview() }
            .onChange(of: scenePhase) { phase in
                if phase != .active { persistDraft() }
            }
    }

    private var presentedContent: some View {
        conversationContent
            .navigationTitle(group?.name ?? L10n.text("group_default_name"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button("Folder") { showFolder = true }
                    Button("Labels") { showLabels = true }
                    Button(
                        model.isPinned(PinTarget(kind: .group, id: groupId))
                            ? L10n.text("pins_unpin")
                            : L10n.source("Pin")
                    ) {
                        model.togglePin(PinTarget(kind: .group, id: groupId))
                    }
                    Button("Members") { showMembers = true }
                        .disabled(group == nil)
                    Button("Poll") { showCreatePoll = true }
                        .disabled(group == nil || !securityReady)
                }
            }
            .sheet(isPresented: $showMembers) { GroupMembersView(groupId: groupId) }
            .sheet(isPresented: $showFolder) {
                FolderAssignmentView(
                    target: FolderTarget(kind: .group, id: groupId),
                    targetName: group?.name ?? L10n.text("group_default_name"))
            }
            .sheet(isPresented: $showLabels) {
                LabelAssignmentView(
                    target: LabelTarget(kind: .group, id: groupId),
                    targetName: group?.name ?? L10n.text("group_default_name"))
            }
            .sheet(isPresented: $showCreatePoll) {
                CreateGroupPollView(
                    groupId: groupId,
                    groupName: group?.name ?? L10n.text("group_default_name"))
            }
            .confirmationDialog(
                "Mention a current member",
                isPresented: $showMentionPicker,
                titleVisibility: .visible
            ) {
                if let group {
                    ForEach(group.members, id: \.self) { peer in
                        Button(memberLabel(peer)) { selectMention(peer) }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(mentionStatus)
            }
            .alert("Send as plain text?", isPresented: $showPlainFallback) {
                Button("Send plain text") { sendPlainFallback() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The exact visible text will carry no semantic mention and trigger no mention notification.")
            }
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
                            draftMentions = []
                        }
                    })
            }
            .sheet(item: $messageEditor) { editor in
                MessageEditEditor(editor: editor) { replacement in
                    try await model.editGroupMessage(
                        group: groupId,
                        targetContentId: editor.contentId,
                        text: replacement)
                }
            }
    }

    private var conversationContent: some View {
        VStack(spacing: 0) {
            LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .group, id: groupId)))
            groupSecurityBanner
            historyContent

            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }

            composerContent
        }
    }

    @ViewBuilder
    private var groupSecurityBanner: some View {
        if let security {
            switch security.level {
            case .upgradeRequired:
                VStack(alignment: .leading, spacing: 6) {
                    Text("Group security upgrade required")
                        .font(.headline)
                    Text("New messages and author-sensitive actions stay blocked until every current device receives a fresh recipient-specific origin capability.")
                        .font(.footnote)
                    Button("Upgrade group security") {
                        Task {
                            do {
                                try await model.upgradeGroupSecurity(group: groupId)
                            } catch {
                                self.error = errorText(error)
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.yellow.opacity(0.16))
            case .upgrading:
                Text(
                    L10n.text(
                        "group_security_upgrading",
                        security.pendingDevices.count))
                    .font(.footnote)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.yellow.opacity(0.16))
                    .accessibilityAddTraits(.updatesFrequently)
            case .recipientAuthenticated where security.legacyHistoryRows > 0:
                Text(
                    L10n.text(
                        "group_security_authenticated_with_legacy",
                        Int(clamping: security.legacyHistoryRows)))
                    .font(.footnote)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.secondary.opacity(0.08))
            case .recipientAuthenticated:
                EmptyView()
            }
        }
    }

    private var historyContent: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                ForEach(polls, id: \.id) { poll in
                    GroupPollCard(
                        poll: poll,
                        authority: authority,
                        memberName: memberLabel,
                        vote: { option in
                            do {
                                try await model.voteGroupPoll(
                                    group: groupId,
                                    pollAuthor: poll.author,
                                    pollId: poll.id,
                                    optionId: option.id)
                            } catch {
                                self.error = errorText(error)
                            }
                        },
                        close: {
                            do {
                                try await model.closeGroupPoll(
                                    group: groupId,
                                    pollAuthor: poll.author,
                                    pollId: poll.id)
                            } catch {
                                self.error = errorText(error)
                            }
                        },
                        moderate: {
                            do {
                                try await model.moderateGroupPollClose(
                                    group: groupId,
                                    pollAuthor: poll.author,
                                    pollId: poll.id)
                            } catch {
                                self.error = errorText(error)
                            }
                        })
                        .disabled(!securityReady)
                }
                ForEach(history, id: \.id) { message in
                    GroupMessageBubble(
                        message: message,
                        memberName: { peer in memberName(peer) },
                        edit: {
                            messageEditor = MessageEditDraft(
                                contentId: message.id, body: message.body)
                        })
                }
                ForEach(scheduled, id: \.id) { message in
                    ScheduledMessageBubble(
                        message: message,
                        edit: { scheduleEditor = ScheduleEditor(message: message) },
                        cancel: { cancel(message) })
                }
                ForEach(attachments, id: \.transferId) { attachment in
                    AttachmentTransferView(attachment: attachment)
                }
            }
            .padding()
        }
    }

    private var composerContent: some View {
        VStack(alignment: .leading, spacing: 6) {
            composerActions
            EphemeralTextControl(lifetime: $ephemeralLifetime)
                .onChange(of: ephemeralLifetime) { value in
                    if value != nil && !draftMentions.isEmpty {
                        draftMentions = []
                        setMentionStatus(L10n.text("mention_disappearing_removed"))
                    }
                }
            if !draftMentions.isEmpty {
                mentionTokens
            }
            Text(mentionStatus)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding()
    }

    private var composerActions: some View {
        HStack {
            AttachmentPickerButton(
                destination: .group(groupId),
                disabled: group == nil || !securityReady
            ) { error in
                self.error = error
            }
            AudioComposerButton(destination: .group(groupId)) { error in
                self.error = error
            }
            .disabled(group == nil || !securityReady)
            Button {
                prepareMentionPicker()
            } label: {
                Image(systemName: "person.badge.plus").font(.title2)
            }
            .disabled(group == nil || !securityReady)
            .accessibilityLabel("Mention an exact current group member")
            mentionEditor
            Button {
                scheduleEditor = ScheduleEditor(body: draft)
            } label: {
                Image(systemName: "calendar.badge.clock").font(.title2)
            }
            .disabled(scheduleDisabled)
            .accessibilityLabel("Schedule message")
            Button {
                send()
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.title2)
            }
            .disabled(sendDisabled)
        }
    }

    private var mentionEditor: some View {
        MentionComposer(
            text: $draft,
            spans: $draftMentions,
            insertion: $mentionInsertion,
            memberName: memberLabel,
            invalidated: { name in
                mentionStatus = L10n.text("mention_removed", name)
            })
            .frame(minHeight: 44, maxHeight: 100)
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(.secondary.opacity(0.45)))
            .disabled(!securityReady)
            .accessibilityLabel("Group message")
    }

    private var mentionTokens: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack {
                ForEach(draftMentions) { mention in
                    Button {
                        removeMention(mention)
                    } label: {
                        Label(memberLabel(mention.target), systemImage: "xmark.circle")
                    }
                    .buttonStyle(.bordered)
                    .accessibilityLabel(
                        L10n.text(
                            "mention_remove_action",
                            memberLabel(mention.target)))
                }
            }
        }
    }

    private var scheduleDisabled: Bool {
        group == nil
            || !securityReady
            || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !draftMentions.isEmpty
    }

    private var sendDisabled: Bool {
        group == nil
            || !securityReady
            || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func memberName(_ peer: String) -> String {
        if peer == model.status?.peer { return L10n.text("group_you") }
        if let contact = model.contacts.first(where: { $0.peer == peer }) {
            return contact.name
        }
        if let position = group?.members.firstIndex(of: peer) {
            return L10n.text("group_member_position", position + 1)
        }
        return L10n.text("group_member_unavailable")
    }

    private func memberLabel(_ peer: String) -> String {
        let base = memberName(peer)
        guard let group else { return base }
        let duplicates = group.members.filter { memberName($0) == base }
        guard duplicates.count > 1 else { return base }
        let position = (group.members.firstIndex(of: peer) ?? 0) + 1
        return L10n.text("group_member_disambiguated", base, position)
    }

    private func setMentionStatus(_ value: String) {
        mentionStatus = value
        UIAccessibility.post(notification: .announcement, argument: value)
    }

    private func prepareMentionPicker() {
        Task {
            do {
                let capability = try await model.groupMentionCapability(group: groupId)
                mentionCapability = capability
                if capability.supported {
                    setMentionStatus(L10n.text("mention_ready"))
                } else {
                    let blockers = capability.issues.map {
                        L10n.text(
                            "mention_blocker",
                            memberLabel($0.peer),
                            mentionIssueName($0.reason))
                    }.joined(separator: ", ")
                    setMentionStatus(L10n.text("mention_unavailable", blockers))
                }
                showMentionPicker = true
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func selectMention(_ peer: String) {
        mentionInsertion = MentionInsertion(target: peer, visible: "@\(memberName(peer))")
        setMentionStatus(L10n.text("mention_inserted", memberLabel(peer)))
    }

    private func removeMention(_ mention: MentionDraftSpan) {
        let source = draft as NSString
        guard mention.start >= 0, mention.end <= source.length, mention.end > mention.start else {
            draftMentions.removeAll { $0.id == mention.id }
            return
        }
        draftMentions.removeAll { $0.id == mention.id }
        reconcileDraftSpans(
            &draftMentions,
            replacing: NSRange(location: mention.start, length: mention.end - mention.start),
            replacementLength: 0)
        draft = source.replacingCharacters(
            in: NSRange(location: mention.start, length: mention.end - mention.start),
            with: "")
        setMentionStatus(
            L10n.text("mention_removed_with_text", memberLabel(mention.target)))
    }

    private func mentionIssueName(_ reason: MentionCapabilityIssueReason) -> String {
        switch reason {
        case .unknown: return L10n.text("mention_capability_unknown")
        case .unsupported: return L10n.text("mention_capability_unsupported")
        }
    }

    private func send() {
        let body = draft
        error = nil
        Task {
            do {
                if let lifetime = ephemeralLifetime {
                    try await model.sendGroupDisappearing(
                        group: groupId,
                        body: body.trimmingCharacters(in: .whitespacesAndNewlines),
                        lifetimeSeconds: lifetime.rawValue)
                    clearDraft()
                    return
                }
                if draftMentions.isEmpty {
                    try await model.sendGroup(
                        group: groupId,
                        body: body.trimmingCharacters(in: .whitespacesAndNewlines))
                    clearDraft()
                    return
                }
                let fresh = try await model.groupMentionCapability(group: groupId)
                guard mentionCapability?.reviewToken == fresh.reviewToken else {
                    mentionCapability = fresh
                    setMentionStatus(
                        "The roster, identity mapping, or capability support changed. Review the exact text and selected mentions, then press Send again.")
                    return
                }
                guard fresh.supported else {
                    showPlainFallback = true
                    return
                }
                let spans = try draftMentions.map { mention -> MentionSpan in
                    MentionSpan(
                        start: try utf8Offset(body, utf16: mention.start),
                        end: try utf8Offset(body, utf16: mention.end),
                        target: mention.target)
                }
                try await model.sendGroupMention(
                    group: groupId,
                    text: body,
                    spans: spans,
                    reviewToken: fresh.reviewToken)
                clearDraft()
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func sendPlainFallback() {
        let body = draft
        Task {
            do {
                try await model.sendGroup(group: groupId, body: body)
                clearDraft()
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func clearDraft() {
        draft = ""
        draftMentions = []
        mentionCapability = nil
        setMentionStatus("Use Mention to choose an exact current roster identity.")
        MentionDraftStore.remove(group: groupId)
    }

    private func revalidateMentionReview() {
        guard !draftMentions.isEmpty else { return }
        Task {
            do {
                let fresh = try await model.groupMentionCapability(group: groupId)
                if mentionCapability?.reviewToken != fresh.reviewToken {
                    mentionCapability = fresh
                    setMentionStatus(
                        "The current roster or member session changed. Review the exact text and mentions before sending.")
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func persistDraft() {
        MentionDraftStore.save(
            group: groupId,
            record: MentionDraftRecord(text: draft, spans: draftMentions))
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

private struct GroupPollCard: View {
    let poll: GroupPoll
    let authority: GroupAuthority?
    let memberName: (String) -> String
    let vote: (PollOption) async -> Void
    let close: () async -> Void
    let moderate: () async -> Void

    @State private var pendingOption: PollOption?
    @State private var showCloseConfirmation = false
    @State private var showModerateConfirmation = false

    private var canModerate: Bool {
        !poll.closed && (authority?.myRole == .owner || authority?.myRole == .admin)
    }

    private var visibleVotes: String {
        let rows = poll.votes.map { vote in
            let choice = poll.options.first(where: { $0.id == vote.optionId })?.text
                ?? L10n.text("poll_unavailable_choice")
            return L10n.text(
                "poll_visible_vote_row",
                memberName(vote.voter),
                choice)
        }
        return rows.isEmpty
            ? L10n.text("poll_no_votes")
            : L10n.text("poll_visible_votes", rows.joined(separator: ", "))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(poll.question).font(.headline)
            Text(
                poll.closed
                    ? (poll.moderatedBy.map {
                        L10n.text(
                            "poll_moderated_policy",
                            memberName($0))
                    } ?? L10n.text("poll_closed_policy"))
                    : L10n.text("poll_open_policy"))
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(poll.options, id: \.id) { option in
                Button {
                    pendingOption = option
                } label: {
                    HStack {
                        Text(option.text)
                        Spacer()
                        Text("\(option.votes)").bold()
                    }
                }
                .buttonStyle(.bordered)
                .tint(option.selectedByMe ? .accentColor : .secondary)
                .disabled(poll.closed || !poll.eligible)
                .accessibilityLabel(
                    L10n.plural(
                        "poll_option_accessibility",
                        count: Int(clamping: option.votes),
                        option.text,
                        Int(clamping: option.votes),
                        option.selectedByMe
                            ? L10n.text("poll_your_choice_suffix")
                            : ""))
            }
            Text(visibleVotes)
                .font(.caption)
                .foregroundStyle(.secondary)
            if poll.canClose {
                Button("Close poll…") { showCloseConfirmation = true }
                    .buttonStyle(.bordered)
            }
            if canModerate {
                Button(authority?.myRole == .owner
                       ? L10n.text("poll_moderate_action")
                       : L10n.text("poll_moderate_request_action")) {
                    showModerateConfirmation = true
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.secondary.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(L10n.text("poll_accessibility", poll.question))
        .alert("Cast visible vote?", isPresented: Binding(
            get: { pendingOption != nil },
            set: { if !$0 { pendingOption = nil } }
        )) {
            Button("Vote") {
                guard let option = pendingOption else { return }
                Task { await vote(option) }
                pendingOption = nil
            }
            Button("Cancel", role: .cancel) { pendingOption = nil }
        } message: {
            Text(
                L10n.text(
                    "poll_vote_confirm",
                    pendingOption?.text ?? ""))
        }
        .alert("Close poll?", isPresented: $showCloseConfirmation) {
            Button("Close poll", role: .destructive) { Task { await close() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(L10n.text("poll_close_confirm", poll.question))
        }
        .alert("Close through group authority?", isPresented: $showModerateConfirmation) {
            Button("Submit", role: .destructive) { Task { await moderate() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The owner sequences an exact signed final snapshot. Admin actions are generation-bound requests.")
        }
    }
}

private struct CreateGroupPollView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let groupId: String
    let groupName: String

    @State private var question = ""
    @State private var options = ["", ""]
    @State private var error: String?
    @State private var saving = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Votes are visible to every member. This is not anonymous. The current roster is fixed as the electorate. The creator may close it; an owner can commit signed moderation, and an admin can request it.")
                        .font(.footnote)
                }
                Section("Question") {
                    TextField("Exact poll question", text: $question, axis: .vertical)
                        .incognitoKeyboard(capitalization: .sentences)
                }
                Section("Choices") {
                    ForEach(options.indices, id: \.self) { index in
                        HStack {
                            TextField(
                                L10n.text("poll_choice_hint", index + 1),
                                text: $options[index],
                                axis: .vertical)
                                .incognitoKeyboard(capitalization: .sentences)
                            if options.count > 2 {
                                Button(role: .destructive) {
                                    options.remove(at: index)
                                } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .accessibilityLabel(
                                    L10n.text(
                                        "poll_remove_choice",
                                        index + 1))
                            }
                        }
                    }
                    Button("Add choice") { options.append("") }
                        .disabled(options.count >= 12)
                }
                if let error {
                    Text(error).foregroundStyle(.red)
                        .accessibilityLabel(
                            L10n.text("poll_error_accessibility", error))
                }
            }
            .navigationTitle(L10n.text("poll_create_title", groupName))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create visible-vote poll") { create() }
                        .disabled(saving)
                }
            }
        }
    }

    private func create() {
        let blank = CharacterSet.whitespacesAndNewlines
        if question.trimmingCharacters(in: blank).isEmpty {
            error = L10n.text("poll_need_question")
        } else if question.utf8.count > 1_024 {
            error = L10n.text("poll_question_too_long")
        } else if options.count < 2 || options.contains(where: {
            $0.trimmingCharacters(in: blank).isEmpty
        }) {
            error = L10n.text("poll_need_choices")
        } else if options.contains(where: { $0.utf8.count > 256 }) {
            error = L10n.text("poll_choice_too_long")
        } else {
            saving = true
            error = nil
            Task {
                do {
                    try await model.createGroupPoll(
                        group: groupId, question: question, options: options)
                    dismiss()
                } catch {
                    self.error = errorText(error)
                    saving = false
                }
            }
        }
    }
}

private struct MentionDraftSpan: Codable, Equatable, Identifiable {
    var id = UUID()
    var start: Int
    var end: Int
    var target: String
}

private struct MentionInsertion: Equatable {
    let id = UUID()
    let target: String
    let visible: String
}

private struct MentionDraftRecord: Codable {
    var text: String = ""
    var spans: [MentionDraftSpan] = []
}

private struct MentionDraftEnvelope: Codable {
    var groups: [String: MentionDraftRecord] = [:]
}

private enum MentionDraftStore {
    private static var url: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("komms", isDirectory: true)
            .appendingPathComponent("mention-drafts.json")
    }

    static func load(group: String) -> MentionDraftRecord {
        guard let data = try? Data(contentsOf: url),
              let envelope = try? JSONDecoder().decode(MentionDraftEnvelope.self, from: data)
        else { return MentionDraftRecord() }
        return envelope.groups[group] ?? MentionDraftRecord()
    }

    static func save(group: String, record: MentionDraftRecord) {
        var envelope = loadEnvelope()
        envelope.groups[group] = record
        write(envelope)
    }

    static func remove(group: String) {
        var envelope = loadEnvelope()
        envelope.groups.removeValue(forKey: group)
        write(envelope)
    }

    private static func loadEnvelope() -> MentionDraftEnvelope {
        guard let data = try? Data(contentsOf: url) else { return MentionDraftEnvelope() }
        return (try? JSONDecoder().decode(MentionDraftEnvelope.self, from: data))
            ?? MentionDraftEnvelope()
    }

    private static func write(_ envelope: MentionDraftEnvelope) {
        let directory = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete])
        guard let data = try? JSONEncoder().encode(envelope),
              (try? data.write(to: url, options: .atomic)) != nil
        else { return }
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        var protected = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? protected.setResourceValues(values)
    }
}

@discardableResult
private func reconcileDraftSpans(
    _ spans: inout [MentionDraftSpan],
    replacing range: NSRange,
    replacementLength: Int
) -> [MentionDraftSpan] {
    let oldEnd = NSMaxRange(range)
    let delta = replacementLength - range.length
    var removed: [MentionDraftSpan] = []
    spans = spans.compactMap { span in
        if range.length == 0 {
            if range.location <= span.start {
                var shifted = span
                shifted.start += delta
                shifted.end += delta
                return shifted
            }
            if range.location >= span.end { return span }
            removed.append(span)
            return nil
        }
        if oldEnd <= span.start {
            var shifted = span
            shifted.start += delta
            shifted.end += delta
            return shifted
        }
        if range.location >= span.end { return span }
        removed.append(span)
        return nil
    }
    return removed
}

private struct MentionComposer: UIViewRepresentable {
    @Binding var text: String
    @Binding var spans: [MentionDraftSpan]
    @Binding var insertion: MentionInsertion?
    let memberName: (String) -> String
    let invalidated: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        view.backgroundColor = .clear
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.isScrollEnabled = true
        view.textContainerInset = UIEdgeInsets(top: 8, left: 5, bottom: 8, right: 5)
        view.accessibilityLabel = L10n.source("Group message")
        view.textAlignment = .natural
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        context.coordinator.parent = self
        if view.text != text {
            let selection = view.selectedRange
            view.text = text
            view.selectedRange = NSRange(
                location: min(selection.location, (text as NSString).length), length: 0)
        }
        if let insertion, insertion.id != context.coordinator.lastInsertion {
            context.coordinator.lastInsertion = insertion.id
            context.coordinator.insert(insertion, into: view)
            DispatchQueue.main.async {
                if self.insertion?.id == insertion.id { self.insertion = nil }
            }
        }
        if view.markedTextRange == nil { context.coordinator.style(view) }
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: MentionComposer
        var lastInsertion: UUID?

        init(_ parent: MentionComposer) { self.parent = parent }

        func textView(
            _ textView: UITextView,
            shouldChangeTextIn range: NSRange,
            replacementText text: String
        ) -> Bool {
            var updated = parent.spans
            let removed = reconcileDraftSpans(
                &updated,
                replacing: range,
                replacementLength: (text as NSString).length)
            parent.spans = updated
            if let removed = removed.first {
                parent.invalidated(parent.memberName(removed.target))
            }
            return true
        }

        func textViewDidChange(_ textView: UITextView) {
            parent.text = textView.text
            if textView.markedTextRange == nil { style(textView) }
        }

        func insert(_ request: MentionInsertion, into view: UITextView) {
            if let marked = view.markedTextRange {
                view.unmarkText()
                _ = marked
            }
            let length = (view.text as NSString).length
            let selected = view.selectedRange
            let range = NSRange(
                location: min(selected.location, length),
                length: min(selected.length, max(0, length - selected.location)))
            var updated = parent.spans
            _ = reconcileDraftSpans(
                &updated,
                replacing: range,
                replacementLength: (request.visible as NSString).length)
            view.textStorage.replaceCharacters(in: range, with: request.visible)
            let end = range.location + (request.visible as NSString).length
            updated.append(MentionDraftSpan(
                start: range.location, end: end, target: request.target))
            updated.sort { $0.start < $1.start }
            parent.spans = updated
            parent.text = view.text
            view.selectedRange = NSRange(location: end, length: 0)
            style(view)
            view.becomeFirstResponder()
        }

        func style(_ view: UITextView) {
            let length = (view.text as NSString).length
            let selection = view.selectedRange
            let full = NSRange(location: 0, length: length)
            view.textStorage.setAttributes([
                .font: UIFont.preferredFont(forTextStyle: .body),
                .foregroundColor: UIColor.label,
            ], range: full)
            for span in parent.spans where span.start >= 0 && span.end <= length && span.end > span.start {
                view.textStorage.addAttributes([
                    .backgroundColor: UIColor.systemYellow.withAlphaComponent(0.28),
                    .underlineStyle: NSUnderlineStyle.single.rawValue,
                    .font: UIFont.preferredFont(forTextStyle: .body).bold(),
                ], range: NSRange(location: span.start, length: span.end - span.start))
            }
            view.selectedRange = selection
        }
    }
}

private extension UIFont {
    func bold() -> UIFont {
        UIFont(descriptor: fontDescriptor.withSymbolicTraits(.traitBold) ?? fontDescriptor, size: 0)
    }
}

private func utf8Offset(_ text: String, utf16 offset: Int) throws -> UInt32 {
    let range = NSRange(location: 0, length: offset)
    guard let stringRange = Range(range, in: text) else {
        throw InputError("mention range must be on a UTF-8 boundary")
    }
    guard let count = UInt32(exactly: text[stringRange].utf8.count) else {
        throw InputError("mention range exceeds the canonical UTF-8 limit")
    }
    return count
}

private struct GroupMessageBubble: View {
    @EnvironmentObject private var model: AppModel
    let message: GroupMessage
    let memberName: (String) -> String
    let edit: () -> Void

    private var outbound: Bool { message.direction == .outbound }
    private var renderedBody: FormattedText {
        let highlights = message.contentKind == .mention
            ? message.mentionSpans.map { TextFormatHighlight(start: $0.start, end: $0.end) }
            : []
        return model.formattedText(source: message.body, highlights: highlights)
    }

    var body: some View {
        HStack {
            if outbound { Spacer(minLength: 40) }
            VStack(alignment: outbound ? .trailing : .leading, spacing: 3) {
                if !outbound {
                    Text(memberName(message.sender))
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                }
                FormattedTextView(formatted: renderedBody)
                    .padding(10)
                    .background(
                        outbound ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15),
                        in: RoundedRectangle(cornerRadius: 12))
                    .textSelection(.enabled)
                if message.contentKind == .mention {
                    ForEach(Array(message.mentionSpans.enumerated()), id: \.offset) { _, span in
                        Text(
                            L10n.text(
                                "mention_label",
                                memberName(span.target)))
                            .font(.caption.bold())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .overlay(Capsule().stroke(.primary))
                            .accessibilityLabel(
                                L10n.text(
                                    "mention_of",
                                    memberName(span.target)))
                    }
                }
                Text(Date(timeIntervalSince1970: TimeInterval(message.timestamp)), style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if message.authentication == .legacyMembership {
                    Text("Legacy group origin")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHint(
                            "Membership-authenticated history; not proof of the individual sender")
                } else if message.authentication == .pendingRecipientAuthentication {
                    Text("Securing recipients")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHint(
                            "Local only until every recipient wrapper is authenticated and queued")
                }
                if message.contentKind == .disappearingText, let expiresAt = message.expiresAt {
                    (
                        Text(L10n.text("removes_prefix"))
                        + Text(
                            Date(
                                timeIntervalSince1970:
                                    TimeInterval(expiresAt)),
                            style: .relative)
                    )
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHint("Removed locally; other devices may retain copies")
                }
                HStack(spacing: 4) {
                    if message.edited {
                        Text(
                            L10n.text(
                                "revision_short",
                                Int(message.editRevision)))
                            .foregroundStyle(.secondary)
                    }
                    if outbound && message.contentKind == .text {
                        Button("Edit", action: edit)
                            .accessibilityLabel("Edit this group message")
                    }
                }
                .font(.caption2)
                if message.edited {
                    EditVersionHistoryView(versions: message.versions)
                }
                if outbound {
                    ForEach(message.deliveries, id: \.peer) { delivery in
                        Text(
                            L10n.text(
                                "group_delivery_row",
                                memberName(delivery.peer),
                                stateText(delivery.state)))
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
        case .queued: return L10n.text("state_queued")
        case .sent: return L10n.text("state_sent")
        case .delivered: return L10n.text("state_delivered")
        case .received: return L10n.text("state_received")
        case .failed: return L10n.text("state_failed")
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
    @State private var rename = ""

    private var group: KommsCore.Group? { model.groups.first { $0.id == groupId } }
    private var ownPeer: String? { model.status?.peer }
    private var authority: GroupAuthority? { model.groupAuthorities[groupId] }
    private var isOwner: Bool { authority?.myRole == .owner }
    private var isAdmin: Bool { authority?.myRole == .admin }
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

                    if isOwner || isAdmin {
                        Section("Group name") {
                            TextField("Group name", text: $rename)
                                .textInputAutocapitalization(.sentences)
                                .autocorrectionDisabled()
                                .incognitoKeyboard(capitalization: .sentences)
                            Button(
                                isOwner
                                    ? L10n.text("group_rename_action")
                                    : L10n.text("group_rename_request_action")
                            ) { renameGroup() }
                                .disabled(working || rename.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                    }

                    Section("Members") {
                        ForEach(authority?.members ?? [], id: \.peer) { member in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(memberName(member.peer))
                                    Text(roleName(member.role))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if isOwner && member.role != .owner {
                                    Menu("Role") {
                                        Button(
                                            member.role == .admin
                                                ? L10n.text("group_make_member")
                                                : L10n.text("group_make_admin")
                                        ) {
                                            setRole(
                                                member.peer,
                                                member.role == .admin ? .member : .admin)
                                        }
                                        Button("Make owner") { transferOwner(member.peer) }
                                    }
                                    .disabled(working)
                                }
                                if (isOwner && member.role != .owner)
                                    || (isAdmin && member.role == .member) {
                                    Button("Remove", role: .destructive) {
                                        removalPeer = member.peer
                                    }
                                    .disabled(working)
                                }
                            }
                        }
                    }

                    if (isOwner || isAdmin) && !candidates.isEmpty {
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
                            .disabled(working || isOwner)
                    } footer: {
                        Text(isOwner
                             ? L10n.text("group_owner_must_transfer")
                             : L10n.text("group_history_stays_after_leaving"))
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .navigationTitle(
                group.map { L10n.text("group_members_title", $0.name) }
                    ?? L10n.text("group_members_heading"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { rename = group?.name ?? "" }
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
                    L10n.text(
                        "group_remove_warning",
                        memberName(removalPeer ?? "")))
            }
            .confirmationDialog(
                L10n.text(
                    "group_leave_named_title",
                    group?.name ?? L10n.text("group_default_name")),
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
        if peer == ownPeer { return L10n.text("group_you") }
        if let contact = model.contacts.first(where: { $0.peer == peer }) {
            return contact.name
        }
        if let position = group?.members.firstIndex(of: peer) {
            return L10n.text("group_member_position", position + 1)
        }
        return L10n.text("group_member_unavailable")
    }

    private func summary(_ group: KommsCore.Group) -> String {
        let count = L10n.plural(
            "group_member_count",
            count: group.members.count)
        guard let authority else { return count }
        let origin = switch group.security {
        case .upgradeRequired: L10n.text("group_origin_upgrade_required")
        case .upgrading: L10n.text("group_origin_upgrade_in_progress")
        case .recipientAuthenticated: L10n.text("group_origin_authenticated")
        }
        return L10n.text(
            "group_authority_security_summary",
            count,
            memberName(authority.owner),
            Int(clamping: authority.generation),
            authority.signed
                ? L10n.text("group_authority_signed")
                : L10n.text("group_authority_legacy"),
            origin)
    }

    private func roleName(_ role: GroupRole) -> String {
        switch role {
        case .owner: return L10n.text("group_role_owner")
        case .admin: return L10n.text("group_role_admin")
        case .member: return L10n.text("group_role_member")
        }
    }

    private func renameGroup() {
        let exact = rename.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !exact.isEmpty else { return }
        working = true
        error = nil
        Task {
            do { try await model.renameGroup(group: groupId, name: exact) }
            catch { self.error = errorText(error) }
            working = false
        }
    }

    private func setRole(_ peer: String, _ role: GroupRole) {
        working = true
        error = nil
        Task {
            do { try await model.setGroupRole(group: groupId, peer: peer, role: role) }
            catch { self.error = errorText(error) }
            working = false
        }
    }

    private func transferOwner(_ peer: String) {
        working = true
        error = nil
        Task {
            do { try await model.transferGroupOwner(group: groupId, peer: peer) }
            catch { self.error = errorText(error) }
            working = false
        }
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
