// The unlocked shell: transport indicators up top (the node's status,
// verbatim), contacts below, and the toolbar for pairing, backup, and lock.

import KommsCore
import SwiftUI

struct MainView: View {
    @EnvironmentObject private var model: AppModel

    @State private var showMyQr = false
    @State private var showAdd = false
    @State private var showBackup = false
    @State private var showSettings = false
    @State private var showCreateGroup = false
    @State private var showFolders = false
    @State private var showLabels = false
    @State private var showPins = false
    @State private var showIcons = false
    @State private var showDevices = false
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
                    StatusSection(status: status)
                }

                Section("Private conversation folder") {
                    Picker("Folder", selection: Binding(
                        get: { model.folderSelection },
                        set: { model.selectFolder($0) })) {
                        Text("All").tag(FolderSelection(kind: .all, id: nil))
                        Text("Unfiled").tag(FolderSelection(kind: .unfiled, id: nil))
                        ForEach(model.folders, id: \.id) { folder in
                            HStack {
                                CustomIconAvatar(
                                    target: CustomIconTarget(kind: .folder, id: folder.id),
                                    label: folder.name,
                                    size: 28)
                                Text(verbatim: folder.name)
                            }
                                .tag(FolderSelection(kind: .folder, id: folder.id))
                                .accessibilityLabel(Text(verbatim: folderSummary(folder)))
                        }
                    }
                    .pickerStyle(.menu)
                    Text("Folder selection is applied first; the label filter below is then applied independently.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Filter conversations by labels") {
                    if model.labels.isEmpty {
                        Text("No labels yet").foregroundStyle(.secondary)
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
                    if model.selectedLabelIds.isEmpty == false {
                        Button("Clear label filter") { model.clearLabelFilter() }
                    }
                }

                if model.pinRows.contains(where: \.pinned) {
                    Section("Pinned") {
                        ForEach(Array(model.pinRows.filter(\.pinned).enumerated()), id: \.offset) { _, row in
                            pinnedLink(row)
                        }
                    }
                }

                Section("Local") {
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

                Section("Contacts") {
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
                        showAdd = true
                    } label: {
                        Label("Add contact", systemImage: "person.badge.plus")
                    }
                    Menu {
                        Button("New group") { showCreateGroup = true }
                        Button("Manage pins") { showPins = true }
                        Button("Manage private icons") { showIcons = true }
                        Button("Linked devices") { showDevices = true }
                        Button("My pairing QR") { showMyQr = true }
                        Button("Backup…") { showBackup = true }
                        Button("Network settings") { showSettings = true }
                        Button("Manage folders") { showFolders = true }
                        Button("Manage labels") { showLabels = true }
                        Button("Lock", role: .destructive) { model.lock() }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showPins) { PinsView() }
            .sheet(isPresented: $showIcons) { CustomIconsView() }
            .sheet(isPresented: $showDevices) { DevicesView() }
            .sheet(isPresented: $showMyQr) { MyBundleView() }
            .sheet(isPresented: $showAdd) { AddContactView() }
            .sheet(isPresented: Binding(
                get: { renameContact != nil },
                set: { if !$0 { renameContact = nil } })) {
                if let contact = renameContact {
                    RenameContactView(contact: contact)
                }
            }
            .sheet(isPresented: $showBackup) { BackupView() }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .sheet(isPresented: $showFolders) { FolderManagerView() }
            .sheet(isPresented: $showLabels) { LabelManagerView() }
            .sheet(isPresented: $showCreateGroup) {
                CreateGroupView { group in
                    showCreateGroup = false
                    navigation.append(GroupRoute(id: group))
                }
            }
        }
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

/// Transport indicators, rendered from the node's status verbatim.
private struct StatusSection: View {
    let status: Status

    private var natText: String {
        switch status.nat {
        case .public: return "public — directly reachable"
        case .private: return "private — behind NAT"
        case .unknown: return "unknown — not probed yet"
        }
    }

    var body: some View {
        Section("This node") {
            LabeledContent("Address") {
                Text(status.address)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }
            LabeledContent("NAT", value: natText)
            LabeledContent("LAN peers", value: String(status.lanPeers.count))
            LabeledContent("Scheduled", value: String(status.scheduled))
            LabeledContent("Queued", value: String(status.queued))
            LabeledContent("Bridging", value: String(status.transit))
            DisclosureGroup("Listen addresses (\(status.listen.count))") {
                ForEach(status.listen, id: \.self) { addr in
                    Text(addr)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
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
