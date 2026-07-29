import KommsCore
import SwiftUI

/// Familiar, bounded consent UI for unknown senders and group proposals.
struct MessageRequestsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var names: [String: String] = [:]
    @State private var busy: Set<String> = []
    @State private var blockCandidate: MessageRequest?
    @State private var error = ""
    @State private var status = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(
                        "People you have not accepted stay separate from contacts and "
                        + "conversation history. Review the preview and safety number "
                        + "before deciding."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }

                if !model.messageRequests.isEmpty {
                    Section("Message requests") {
                        ForEach(model.messageRequests, id: \.id) { request in
                            messageRequest(request)
                        }
                    }
                }

                if !model.groupInvitations.isEmpty {
                    Section("Group invitations") {
                        ForEach(model.groupInvitations, id: \.id) { invitation in
                            groupInvitation(invitation)
                        }
                    }
                }

                if model.messageRequests.isEmpty && model.groupInvitations.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "tray").font(.title2)
                        Text("No pending requests").font(.headline)
                        Text("New requests will remain separate until you decide.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .accessibilityElement(children: .combine)
                }
            }
            .navigationTitle("Message requests")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { await model.refresh() }
            .alert("Request could not be changed", isPresented: Binding(
                get: { !error.isEmpty },
                set: { if !$0 { error = "" } }
            )) {
                Button("OK", role: .cancel) { error = "" }
            } message: {
                Text(error)
            }
            .confirmationDialog(
                "Block this sender?",
                isPresented: Binding(
                    get: { blockCandidate != nil },
                    set: { if !$0 { blockCandidate = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Block", role: .destructive) {
                    guard let request = blockCandidate else { return }
                    blockCandidate = nil
                    perform(request.id) {
                        try await model.blockMessageRequest(request.id)
                        status = "Sender blocked locally."
                    }
                }
                Button("Cancel", role: .cancel) { blockCandidate = nil }
            } message: {
                Text(
                    "Blocking removes this sender’s local capabilities and queues. "
                    + "It cannot delete remote copies."
                )
            }
            .safeAreaInset(edge: .bottom) {
                if !status.isEmpty {
                    Text(status)
                        .font(.footnote)
                        .padding(.horizontal)
                        .padding(.vertical, 8)
                        .frame(maxWidth: .infinity)
                        .background(.thinMaterial)
                        .accessibilityAddTraits(.updatesFrequently)
                }
            }
        }
    }

    @ViewBuilder
    private func messageRequest(_ request: MessageRequest) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Message from someone new").font(.headline)
            Text(Date(timeIntervalSince1970: TimeInterval(request.expiresAt)), style: .relative)
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityLabel(
                    "Request expires \(Date(timeIntervalSince1970: TimeInterval(request.expiresAt)).formatted())"
                )
            Text(request.preview.isEmpty ? "No text preview" : request.preview)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(ThemePalette.surfaceRaised, in: RoundedRectangle(cornerRadius: 8))
            Text("Safety number: \(request.safetyNumber)")
                .font(.caption.monospaced())
                .textSelection(.enabled)
            TextField(
                "Private contact name",
                text: Binding(
                    get: { names[request.id] ?? "New contact" },
                    set: { names[request.id] = $0 }
                )
            )
            .textContentType(.nickname)
            .autocorrectionDisabled()
            .privacySensitive()
            .incognitoKeyboard(capitalization: .words)
            VStack(alignment: .leading, spacing: 8) {
                Button("Accept") {
                    let name = (names[request.id] ?? "New contact")
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !name.isEmpty else {
                        error = "Choose a private contact name."
                        return
                    }
                    perform(request.id) {
                        _ = try await model.acceptMessageRequest(request.id, name: name)
                        status = "Request accepted. Its first message is now in conversation history."
                    }
                }
                .buttonStyle(.borderedProminent)
                .frame(minHeight: 44)
                Button("Delete", role: .destructive) {
                    perform(request.id) {
                        try await model.deleteMessageRequest(request.id)
                        status = "Request deleted locally."
                    }
                }
                .frame(minHeight: 44)
                Button("Block", role: .destructive) { blockCandidate = request }
                    .frame(minHeight: 44)
            }
            .disabled(busy.contains(request.id))
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func groupInvitation(_ invitation: GroupInvitation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(invitation.name.isEmpty ? "Unnamed group" : invitation.name)
                .font(.headline)
            Text(
                "\(invitation.memberCount) "
                + (invitation.memberCount == 1 ? "member" : "members")
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            Text(
                "Joining creates group state only after you accept. "
                + "Earlier group history is not imported."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                Button("Join group") {
                    perform(invitation.id) {
                        _ = try await model.acceptGroupInvitation(invitation.id)
                        status = "Group invitation accepted."
                    }
                }
                .buttonStyle(.borderedProminent)
                .frame(minHeight: 44)
                Button("Delete", role: .destructive) {
                    perform(invitation.id) {
                        try await model.deleteGroupInvitation(invitation.id)
                        status = "Group invitation deleted locally."
                    }
                }
                .frame(minHeight: 44)
            }
            .disabled(busy.contains(invitation.id))
        }
        .padding(.vertical, 4)
    }

    private func perform(
        _ id: String,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        guard !busy.contains(id) else { return }
        busy.insert(id)
        Task { @MainActor in
            defer { busy.remove(id) }
            do {
                try await operation()
            } catch let ffi as FfiError {
                error = ffi.reasonText
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
