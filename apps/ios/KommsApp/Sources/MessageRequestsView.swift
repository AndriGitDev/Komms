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
                    Text(L10n.text("message_requests_intro"))
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
                        status = L10n.text("request_blocked_status")
                    }
                }
                Button("Cancel", role: .cancel) { blockCandidate = nil }
            } message: {
                Text(L10n.text("message_request_block_explanation"))
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
                    L10n.text(
                        "message_request_expires",
                        Date(
                            timeIntervalSince1970:
                                TimeInterval(request.expiresAt)).formatted())
                )
            Text(
                request.preview.isEmpty
                    ? L10n.text("request_no_preview")
                    : request.preview)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(ThemePalette.surfaceRaised, in: RoundedRectangle(cornerRadius: 8))
            Text(L10n.text("message_request_safety", request.safetyNumber))
                .font(.caption.monospaced())
                .textSelection(.enabled)
            TextField(
                "Private contact name",
                text: Binding(
                    get: {
                        names[request.id]
                            ?? L10n.text("message_request_default_name")
                    },
                    set: { names[request.id] = $0 }
                )
            )
            .textContentType(.nickname)
            .autocorrectionDisabled()
            .privacySensitive()
            .incognitoKeyboard(capitalization: .words)
            VStack(alignment: .leading, spacing: 8) {
                Button("Accept") {
                    let name = (
                        names[request.id]
                            ?? L10n.text("message_request_default_name")
                    )
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !name.isEmpty else {
                        error = L10n.text("request_name_required")
                        return
                    }
                    perform(request.id) {
                        _ = try await model.acceptMessageRequest(request.id, name: name)
                        status = L10n.text("request_accepted_status")
                    }
                }
                .buttonStyle(.borderedProminent)
                .frame(minHeight: 44)
                Button("Delete", role: .destructive) {
                    perform(request.id) {
                        try await model.deleteMessageRequest(request.id)
                        status = L10n.text("request_deleted_status")
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
            Text(
                invitation.name.isEmpty
                    ? L10n.text("group_unnamed")
                    : invitation.name)
                .font(.headline)
            Text(
                L10n.plural(
                    "group_member_count",
                    count: Int(invitation.memberCount)))
            .font(.caption)
            .foregroundStyle(.secondary)
            Text(L10n.text("group_invitation_explanation"))
            .font(.footnote)
            .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                Button("Join group") {
                    perform(invitation.id) {
                        _ = try await model.acceptGroupInvitation(invitation.id)
                        status = L10n.text("group_invitation_accepted_status")
                    }
                }
                .buttonStyle(.borderedProminent)
                .frame(minHeight: 44)
                Button("Delete", role: .destructive) {
                    perform(invitation.id) {
                        try await model.deleteGroupInvitation(invitation.id)
                        status = L10n.text("group_invitation_deleted_status")
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
                error = L10n.error(ffi)
            } catch {
                self.error = L10n.error(error)
            }
        }
    }
}
