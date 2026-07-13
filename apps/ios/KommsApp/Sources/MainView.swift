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

                Section("Contacts") {
                    if model.contacts.isEmpty {
                        Text("No contacts yet — pair with a friend's QR code.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.contacts, id: \.peer) { contact in
                        NavigationLink(value: contact.peer) {
                            HStack {
                                Text(contact.name)
                                if contact.verified {
                                    Image(systemName: "checkmark.seal.fill")
                                        .foregroundStyle(.green)
                                        .accessibilityLabel("verified")
                                }
                            }
                        }
                    }
                }

                Section("Groups") {
                    if model.groups.isEmpty {
                        Text("No groups yet — create one from stored contacts.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.groups.sorted(by: { $0.name < $1.name }), id: \.id) { group in
                        NavigationLink(value: GroupRoute(id: group.id)) {
                            VStack(alignment: .leading) {
                                Text(group.name)
                                Text("\(group.members.count) "
                                     + (group.members.count == 1 ? "member" : "members"))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
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
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button {
                        showAdd = true
                    } label: {
                        Label("Add contact", systemImage: "person.badge.plus")
                    }
                    Menu {
                        Button("New group") { showCreateGroup = true }
                        Button("My pairing QR") { showMyQr = true }
                        Button("Backup…") { showBackup = true }
                        Button("Network settings") { showSettings = true }
                        Button("Lock", role: .destructive) { model.lock() }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showMyQr) { MyBundleView() }
            .sheet(isPresented: $showAdd) { AddContactView() }
            .sheet(isPresented: $showBackup) { BackupView() }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .sheet(isPresented: $showCreateGroup) {
                CreateGroupView { group in
                    showCreateGroup = false
                    navigation.append(GroupRoute(id: group))
                }
            }
        }
    }
}

private struct GroupRoute: Hashable {
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
