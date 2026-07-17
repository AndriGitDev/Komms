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
    @State private var mentionStatus = "Use Mention to choose an exact current roster identity."
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
            .navigationTitle(group?.name ?? "Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button("Folder") { showFolder = true }
                    Button("Labels") { showLabels = true }
                    Button(model.isPinned(PinTarget(kind: .group, id: groupId)) ? "Unpin" : "Pin") {
                        model.togglePin(PinTarget(kind: .group, id: groupId))
                    }
                    Button("Members") { showMembers = true }
                        .disabled(group == nil)
                    Button("Poll") { showCreatePoll = true }
                        .disabled(group == nil)
                }
            }
            .sheet(isPresented: $showMembers) { GroupMembersView(groupId: groupId) }
            .sheet(isPresented: $showFolder) {
                FolderAssignmentView(
                    target: FolderTarget(kind: .group, id: groupId),
                    targetName: group?.name ?? "Group")
            }
            .sheet(isPresented: $showLabels) {
                LabelAssignmentView(
                    target: LabelTarget(kind: .group, id: groupId),
                    targetName: group?.name ?? "Group")
            }
            .sheet(isPresented: $showCreatePoll) {
                CreateGroupPollView(groupId: groupId, groupName: group?.name ?? "Group")
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
                        setMentionStatus("Semantic mentions were removed because disappearing text is a distinct authenticated content type.")
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
                disabled: group == nil
            ) { error in
                self.error = error
            }
            AudioComposerButton(destination: .group(groupId)) { error in
                self.error = error
            }
            .disabled(group == nil)
            Button {
                prepareMentionPicker()
            } label: {
                Image(systemName: "person.badge.plus").font(.title2)
            }
            .disabled(group == nil)
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
                mentionStatus = "Mention of \(name) was removed because its text changed."
            })
            .frame(minHeight: 38, maxHeight: 100)
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(.secondary.opacity(0.45)))
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
                    .accessibilityLabel("Remove mention of \(memberLabel(mention.target))")
                }
            }
        }
    }

    private var scheduleDisabled: Bool {
        group == nil
            || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !draftMentions.isEmpty
    }

    private var sendDisabled: Bool {
        group == nil || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func memberName(_ peer: String) -> String {
        if peer == model.status?.peer { return "You" }
        if let contact = model.contacts.first(where: { $0.peer == peer }) {
            return contact.name
        }
        if let position = group?.members.firstIndex(of: peer) {
            return "Group member \(position + 1)"
        }
        return "Unavailable group member"
    }

    private func memberLabel(_ peer: String) -> String {
        let base = memberName(peer)
        guard let group else { return base }
        let duplicates = group.members.filter { memberName($0) == base }
        guard duplicates.count > 1 else { return base }
        let position = (group.members.firstIndex(of: peer) ?? 0) + 1
        return "\u{2068}\(base)\u{2069}, group member \(position)"
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
                    setMentionStatus(
                        "All current members support semantic mentions. Review the exact final text before Send.")
                } else {
                    let blockers = capability.issues.map {
                        "\(memberLabel($0.peer)) (\(String(describing: $0.reason).lowercased()))"
                    }.joined(separator: ", ")
                    setMentionStatus(
                        "Semantic mentions are unavailable for \(blockers). Send can use plain text with no mention notification.")
                }
                showMentionPicker = true
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func selectMention(_ peer: String) {
        mentionInsertion = MentionInsertion(target: peer, visible: "@\(memberName(peer))")
        setMentionStatus(
            "Mention of \(memberLabel(peer)) inserted. Review the exact final text before Send.")
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
        setMentionStatus("Mention of \(memberLabel(mention.target)) removed with its visible text.")
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
                ?? "unavailable choice"
            return "\(memberName(vote.voter)) → \(choice)"
        }
        return rows.isEmpty ? "No votes yet." : "Visible votes: \(rows.joined(separator: ", "))."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(poll.question).font(.headline)
            Text(poll.closed
                 ? (poll.moderatedBy.map {
                    "Closed by owner \(memberName($0)) · signed moderation snapshot · votes visible to all members"
                 } ?? "Closed · final creator snapshot · votes visible to all members")
                 : "Open · single choice · votes visible to all members · not anonymous")
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
                    "\(option.text), \(option.votes) votes"
                    + (option.selectedByMe ? ", your choice" : ""))
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
                       ? "Moderate close…" : "Request moderation close…") {
                    showModerateConfirmation = true
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.secondary.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Poll: \(poll.question)")
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
            Text("Choose “\(pendingOption?.text ?? "")”? Your identity and choice are visible to group members. You can change it until the poll closes.")
        }
        .alert("Close poll?", isPresented: $showCloseConfirmation) {
            Button("Close poll", role: .destructive) { Task { await close() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Close “\(poll.question)” with the visible vote heads shown now? This cannot be undone.")
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
                            TextField("Choice \(index + 1)", text: $options[index], axis: .vertical)
                                .incognitoKeyboard(capitalization: .sentences)
                            if options.count > 2 {
                                Button(role: .destructive) {
                                    options.remove(at: index)
                                } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .accessibilityLabel("Remove choice \(index + 1)")
                            }
                        }
                    }
                    Button("Add choice") { options.append("") }
                        .disabled(options.count >= 12)
                }
                if let error {
                    Text(error).foregroundStyle(.red).accessibilityLabel("Poll error: \(error)")
                }
            }
            .navigationTitle("Create poll in \(groupName)")
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
            error = "Enter a poll question."
        } else if question.utf8.count > 1_024 {
            error = "The poll question is longer than 1,024 UTF-8 bytes."
        } else if options.count < 2 || options.contains(where: {
            $0.trimmingCharacters(in: blank).isEmpty
        }) {
            error = "Enter at least two non-empty choices."
        } else if options.contains(where: { $0.utf8.count > 256 }) {
            error = "Each poll choice must be at most 256 UTF-8 bytes."
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
        view.accessibilityLabel = "Group message"
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
                        Text("Mention: \(memberName(span.target))")
                            .font(.caption.bold())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .overlay(Capsule().stroke(.primary))
                            .accessibilityLabel("Mention of \(memberName(span.target))")
                    }
                }
                Text(Date(timeIntervalSince1970: TimeInterval(message.timestamp)), style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if message.contentKind == .disappearingText, let expiresAt = message.expiresAt {
                    Text("Removes \(Date(timeIntervalSince1970: TimeInterval(expiresAt)), style: .relative)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityHint("Removed locally; other devices may retain copies")
                }
                HStack(spacing: 4) {
                    if message.edited {
                        Text("edited r\(message.editRevision)")
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
                            Button(isOwner ? "Rename" : "Request rename") { renameGroup() }
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
                                        Button(member.role == .admin ? "Make member" : "Make admin") {
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
                             ? "Transfer ownership before leaving."
                             : "Message history stays stored on this device after leaving.")
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
        if let contact = model.contacts.first(where: { $0.peer == peer }) {
            return contact.name
        }
        if let position = group?.members.firstIndex(of: peer) {
            return "Group member \(position + 1)"
        }
        return "Unavailable group member"
    }

    private func summary(_ group: KommsCore.Group) -> String {
        let count = "\(group.members.count) "
            + (group.members.count == 1 ? "member" : "members")
        guard let authority else { return count }
        return "\(count) · \(memberName(authority.owner)) owns this group · generation \(authority.generation) · \(authority.signed ? "signed authority" : "legacy authority")."
    }

    private func roleName(_ role: GroupRole) -> String {
        switch role {
        case .owner: return "owner"
        case .admin: return "admin"
        case .member: return "member"
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
