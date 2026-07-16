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
    @State private var messageEditor: MessageEditDraft?

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
