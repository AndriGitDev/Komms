// The unlocked shell: transport indicators up top (the node's status,
// verbatim), contacts below, and the toolbar for pairing, backup, and lock.

import KommsCore
import SwiftUI

struct MainView: View {
    @EnvironmentObject private var model: AppModel

    @State private var showMyQr = false
    @State private var showAdd = false
    @State private var showSettings = false
    @State private var showCreateGroup = false
    @State private var showNodeDetails = false
    @State private var showFilters = false
    @State private var renameContact: Contact?
    @State private var navigation = NavigationPath()

    var body: some View {
        NavigationStack(path: $navigation) {
            List {
                if !model.notices.isEmpty {
                    Section("Notices") {
                        ForEach(model.notices.indices, id: \.self) { i in
                            Text(model.notices[i]).font(.footnote)
                        }
                        Button("Clear") { model.notices = [] }
                            .font(.footnote)
                    }
                }

                if let status = model.status {
                    Section {
                        Button {
                            showNodeDetails = true
                        } label: {
                            NodeSummaryRow(status: status)
                        }
                        .buttonStyle(.plain)
                    }
                }

                if model.pinRows.contains(where: \.pinned) {
                    Section("Pinned") {
                        ForEach(Array(model.pinRows.filter(\.pinned).enumerated()), id: \.offset) { _, row in
                            pinnedLink(row)
                        }
                    }
                }

                if model.contacts.isEmpty && model.groups.isEmpty {
                    Section {
                        VStack(spacing: 10) {
                            Image(systemName: "bubble.left.and.bubble.right")
                                .font(.title)
                                .foregroundStyle(ThemePalette.accent)
                            Text("Your private inbox starts here")
                                .font(.headline)
                            Text("Pair with someone you trust, or keep a private note on this device.")
                                .font(.subheadline)
                                .foregroundStyle(ThemePalette.textSecondary)
                                .multilineTextAlignment(.center)
                            Button("Pair a contact") { showAdd = true }
                                .buttonStyle(.borderedProminent)
                                .tint(ThemePalette.accent)
                                .foregroundStyle(ThemePalette.onAccent)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                    }
                }

                Section("On this device") {
                    if model.targetMatchesLabelFilter(LabelTarget(kind: .noteToSelf, id: nil)) &&
                        !model.isPinned(PinTarget(kind: .noteToSelf, id: nil)) {
                      NavigationLink(value: NoteRoute(id: model.noteToSelfId())) {
                        HStack {
                            CustomIconAvatar(target: .init(kind: .noteToSelf, id: nil), label: "Note to self")
                            VStack(alignment: .leading) {
                                Text("Note to self")
                                Text("Local only")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .noteToSelf, id: nil)))
                            }
                        }
                      }
                    }
                }

                Section("Private conversations") {
                    if model.contacts.isEmpty {
                        Text("No contacts yet — pair with a friend's QR code.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.contacts.filter { model.targetMatchesLabelFilter(LabelTarget(kind: .peer, id: $0.peer)) && !model.isPinned(PinTarget(kind: .peer, id: $0.peer)) }, id: \.peer) { contact in
                        NavigationLink(value: contact.peer) {
                            HStack {
                                CustomIconAvatar(target: .init(kind: .contact, id: contact.peer), label: contact.name)
                                VStack(alignment: .leading) {
                                    HStack {
                                        Text(verbatim: contact.name)
                                        if contact.verified {
                                            Image(systemName: "checkmark.seal.fill")
                                                .foregroundStyle(.green)
                                                .accessibilityLabel("verified")
                                        }
                                    }
                                    LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .peer, id: contact.peer)))
                                }
                            }
                        }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button("Rename") { renameContact = contact }
                        }
                        .contextMenu {
                            Button("Rename private petname") { renameContact = contact }
                        }
                    }
                }

                Section("Groups") {
                    if model.groups.isEmpty {
                        Text("No groups yet — create one from stored contacts.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.groups.filter { model.targetMatchesLabelFilter(LabelTarget(kind: .group, id: $0.id)) && !model.isPinned(PinTarget(kind: .group, id: $0.id)) }, id: \.id) { group in
                        NavigationLink(value: GroupRoute(id: group.id)) {
                            HStack {
                                CustomIconAvatar(target: .init(kind: .group, id: group.id), label: group.name)
                                VStack(alignment: .leading) {
                                    Text(group.name)
                                    Text("\(group.members.count) "
                                         + (group.members.count == 1 ? "member" : "members"))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    LabelBadgeRow(labels: model.labelsForTarget(LabelTarget(kind: .group, id: group.id)))
                                }
                            }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(ThemePalette.background)
            .navigationTitle("Komms")
            .navigationDestination(for: String.self) { peer in
                ChatView(peer: peer)
            }
            .navigationDestination(for: GroupRoute.self) { route in
                GroupChatView(groupId: route.id)
            }
            .navigationDestination(for: NoteRoute.self) { route in
                NoteToSelfView(conversationId: route.id)
            }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button {
                        showFilters = true
                    } label: {
                        Label("Filter conversations", systemImage: filterIcon)
                    }
                    Button {
                        showAdd = true
                    } label: {
                        Label("Add contact", systemImage: "person.badge.plus")
                    }
                    Menu {
                        Button("New group") { showCreateGroup = true }
                        Button("My pairing QR") { showMyQr = true }
                        Button("Settings") { showSettings = true }
                        Button("Lock", role: .destructive) { model.lock() }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showNodeDetails) {
                if let status = model.status {
                    NodeDetailsView(status: status)
                }
            }
            .sheet(isPresented: $showFilters) { ConversationFiltersView() }
            .sheet(isPresented: $showMyQr) { MyBundleView() }
            .sheet(isPresented: $showAdd) { AddContactView() }
            .sheet(isPresented: Binding(
                get: { renameContact != nil },
                set: { if !$0 { renameContact = nil } })) {
                if let contact = renameContact {
                    RenameContactView(contact: contact)
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .sheet(isPresented: $showCreateGroup) {
                CreateGroupView { group in
                    showCreateGroup = false
                    navigation.append(GroupRoute(id: group))
                }
            }
        }
    }

    private var filterIcon: String {
        let filtered = model.folderSelection.kind != .all || !model.selectedLabelIds.isEmpty
        return filtered ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle"
    }

    @ViewBuilder private func pinnedLink(_ row: PinConversation) -> some View {
        switch row.target.kind {
        case .peer:
            if let id = row.target.id {
                let name = row.displayName ?? String(id.prefix(12))
                NavigationLink(value: id) {
                    HStack {
                        CustomIconAvatar(target: .init(kind: .contact, id: id), label: name)
                        Text(verbatim: name)
                    }
                }
            }
        case .group:
            if let id = row.target.id {
                let name = row.displayName ?? "Group"
                NavigationLink(value: GroupRoute(id: id)) {
                    HStack {
                        CustomIconAvatar(target: .init(kind: .group, id: id), label: name)
                        Text(verbatim: name)
                    }
                }
            }
        case .noteToSelf:
            NavigationLink(value: NoteRoute(id: model.noteToSelfId())) {
                HStack {
                    CustomIconAvatar(target: .init(kind: .noteToSelf, id: nil), label: "Note to self")
                    Text("Note to self")
                }
            }
        }
    }
}

private struct GroupRoute: Hashable {
    let id: String
}

private struct NoteRoute: Hashable {
    let id: String
}

/// Human-readable state first; raw transport diagnostics are one tap away.
private struct NodeSummaryRow: View {
    let status: Status

    private var symbol: String {
        switch status.nat {
        case .public: return "checkmark.shield.fill"
        case .private: return "shield.lefthalf.filled"
        case .unknown: return "hourglass"
        }
    }

    private var summary: String {
        switch status.nat {
        case .public: return "Directly reachable"
        case .private: return "Connected behind NAT"
        case .unknown: return "Checking reachability"
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(status.nat == .unknown ? ThemePalette.warning : ThemePalette.success)
                .frame(width: 34, height: 34)
                .background(ThemePalette.surfaceRaised, in: Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text("Node running")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(ThemePalette.textPrimary)
                Text("\(summary) · \(status.lanPeers.count) LAN \(status.lanPeers.count == 1 ? "peer" : "peers")")
                    .font(.caption)
                    .foregroundStyle(ThemePalette.textSecondary)
            }
            Spacer()
            if status.queued > 0 {
                Text("\(status.queued) queued")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(ThemePalette.warning)
            }
            Image(systemName: "chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(ThemePalette.textSecondary)
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityHint("Shows network details")
    }
}

private struct NodeDetailsView: View {
    let status: Status
    @Environment(\.dismiss) private var dismiss

    private var natText: String {
        switch status.nat {
        case .public: return "Public — directly reachable"
        case .private: return "Private — behind NAT"
        case .unknown: return "Unknown — not probed yet"
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Identity") {
                    LabeledContent("Address") {
                        Text(status.address)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }
                Section("Reachability") {
                    LabeledContent("NAT", value: natText)
                    LabeledContent("LAN peers", value: String(status.lanPeers.count))
                    LabeledContent("Listen addresses", value: String(status.listen.count))
                    ForEach(status.listen, id: \.self) { address in
                        Text(address)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                Section("Delivery") {
                    LabeledContent("Scheduled", value: String(status.scheduled))
                    LabeledContent("Queued", value: String(status.queued))
                    LabeledContent("Bridging", value: String(status.transit))
                }
            }
            .scrollContentBackground(.hidden)
            .background(ThemePalette.background)
            .navigationTitle("Node details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

private struct ConversationFiltersView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Folder") {
                    Picker("Show", selection: Binding(
                        get: { model.folderSelection },
                        set: { model.selectFolder($0) })) {
                        Text("All conversations")
                            .tag(FolderSelection(kind: .all, id: nil))
                        Text("Unfiled")
                            .tag(FolderSelection(kind: .unfiled, id: nil))
                        ForEach(model.folders, id: \.id) { folder in
                            Text(verbatim: folder.name)
                                .tag(FolderSelection(kind: .folder, id: folder.id))
                                .accessibilityLabel(Text(verbatim: folderSummary(folder)))
                        }
                    }
                }

                Section {
                    if model.labels.isEmpty {
                        Text("No labels yet")
                            .foregroundStyle(ThemePalette.textSecondary)
                    }
                    ForEach(model.labels, id: \.id) { label in
                        Toggle(isOn: Binding(
                            get: { model.selectedLabelIds.contains(label.id) },
                            set: { model.setLabelSelected(label.id, selected: $0) })) {
                            LabelChip(label: label)
                        }
                    }
                    Picker("Matching", selection: Binding(
                        get: { model.labelFilterMode },
                        set: { model.setLabelFilterMode($0) })) {
                        Text("Match any").tag(LabelMatchMode.any)
                        Text("Match all").tag(LabelMatchMode.all)
                    }
                    .pickerStyle(.segmented)
                } header: {
                    Text("Labels")
                } footer: {
                    Text("The folder is applied first, followed by the label filter.")
                }

                if model.folderSelection.kind != .all || !model.selectedLabelIds.isEmpty {
                    Section {
                        Button("Clear all filters", role: .destructive) {
                            model.selectFolder(FolderSelection(kind: .all, id: nil))
                            model.clearLabelFilter()
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(ThemePalette.background)
            .navigationTitle("Filter conversations")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

/// This node's prekey bundle as QR + pasteable hex — what a friend scans.
private struct MyBundleView: View {
    @EnvironmentObject private var model: AppModel
    @State private var bundleHex: String?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if let bundleHex {
                        QrCodeView(text: bundleQrText(bundleHex))
                            .frame(width: 260, height: 260)
                        Text("Or share the hex (interoperable with the desktop app and `kult add`):")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Text(bundleHex)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .padding(.horizontal)
                    } else if let error {
                        Text(error).foregroundStyle(.red)
                    } else {
                        ProgressView()
                    }
                }
                .padding()
            }
            .navigationTitle("My pairing QR")
            .task {
                do {
                    bundleHex = try await model.myBundleHex()
                } catch {
                    self.error = errorText(error)
                }
            }
        }
    }
}
