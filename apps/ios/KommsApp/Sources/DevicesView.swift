import KommsCore
import SwiftUI
import UIKit

/// Native C2 manager for account-authorized physical installations.
struct DevicesView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var showSource = false
    @State private var showTarget = false
    @State private var showSync = false
    @State private var approvalKind: DeviceApprovalKind?
    @State private var showContinueAuthority = false
    @State private var renameDevice: LinkedDevice?
    @State private var renameText = ""
    @State private var revokeDevice: LinkedDevice?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Each installation has independent authenticated keys. Revocation is permanent and immediately excludes that exact device from new delivery and sync.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if !model.deviceAuthorityConflicts.isEmpty {
                    Section("Security conflicts") {
                        ForEach(
                            Array(model.deviceAuthorityConflicts.enumerated()),
                            id: \.offset
                        ) { entry in
                            Text(conflictText(entry.element))
                                .foregroundStyle(ThemePalette.danger)
                                .textSelection(.enabled)
                        }
                    }
                }
                if !model.contactAuthorityConflicts.isEmpty {
                    Section("Contact security conflicts") {
                        ForEach(
                            Array(model.contactAuthorityConflicts.enumerated()),
                            id: \.offset
                        ) { entry in
                            Text(contactConflictText(entry.element))
                                .foregroundStyle(ThemePalette.danger)
                                .textSelection(.enabled)
                        }
                    }
                }
                Section("Devices") {
                    ForEach(model.linkedDevices, id: \.id) { device in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(verbatim: device.name).font(.headline)
                                if device.current { Text("This device").badgeStyle() }
                                if device.revokedAt != nil { Text("Revoked").badgeStyle() }
                            }
                            Text(device.id).font(.caption2.monospaced()).textSelection(.enabled)
                            if device.revokedAt == nil {
                                HStack {
                                    Button("Rename") {
                                        renameText = device.name
                                        renameDevice = device
                                    }
                                    if !device.current {
                                        Button("Copy sync") { exportSync(device) }
                                        Button("Revoke", role: .destructive) { revokeDevice = device }
                                    }
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Linked devices")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Link another device") { showSource = true }
                        Button("Link this new device") { showTarget = true }
                        Button("Approve another device’s link") {
                            approvalKind = .link
                        }
                        Button("Approve another device’s change") {
                            approvalKind = .authority
                        }
                        Button("Continue pending device change") {
                            showContinueAuthority = true
                        }
                        Button("Import encrypted sync") { showSync = true }
                    } label: { Label("Device actions", systemImage: "plus") }
                }
            }
            .task { await model.refreshDevices() }
            .sheet(isPresented: $showSource) { DeviceLinkSourceView() }
            .sheet(isPresented: $showTarget) { DeviceLinkTargetView() }
            .sheet(isPresented: $showSync) { DeviceSyncImportView() }
            .sheet(item: $approvalKind) { DeviceApprovalView(kind: $0) }
            .sheet(isPresented: $showContinueAuthority) {
                PendingDeviceAuthorityView()
            }
            .alert("Rename linked device", isPresented: Binding(
                get: { renameDevice != nil }, set: { if !$0 { renameDevice = nil } })) {
                TextField("Signed device name", text: $renameText)
                    .incognitoKeyboard(capitalization: .words)
                Button("Cancel", role: .cancel) { renameDevice = nil }
                Button("Rename") {
                    guard let device = renameDevice else { return }
                    Task {
                        do { try await model.renameLinkedDevice(device: device.id, name: renameText) }
                        catch {
                            self.error = errorText(error)
                            if self.error?.contains("additional active-device approval") == true {
                                showContinueAuthority = true
                            }
                        }
                        renameDevice = nil
                    }
                }
            }
            .confirmationDialog(
                "Permanently revoke \(revokeDevice?.name ?? "device")?",
                isPresented: Binding(
                    get: { revokeDevice != nil }, set: { if !$0 { revokeDevice = nil } }),
                titleVisibility: .visible
            ) {
                Button("Revoke permanently", role: .destructive) {
                    guard let device = revokeDevice else { return }
                    Task {
                        do { try await model.revokeLinkedDevice(device: device.id, confirmed: true) }
                        catch {
                            self.error = errorText(error)
                            if self.error?.contains("additional active-device approval") == true {
                                showContinueAuthority = true
                            }
                        }
                        revokeDevice = nil
                    }
                }
                Button("Cancel", role: .cancel) { revokeDevice = nil }
            } message: {
                Text("This cannot be undone. The exact device loses new delivery and sync access.")
            }
        }
    }

    private func exportSync(_ device: LinkedDevice) {
        Task {
            do {
                UIPasteboard.general.string = try await model.exportDeviceSync(device: device.id)
            } catch { self.error = errorText(error) }
        }
    }

    private func conflictText(_ conflict: DeviceAuthorityConflict) -> String {
        switch conflict.kind {
        case .fork:
            "Concurrent device-authority branches were detected in recovery epoch \(conflict.recoveryEpoch). Authority is fail-closed and requires offline recovery."
        case .recovery:
            "Different recoveries claim epoch \(conflict.recoveryEpoch). Authority is fail-closed; re-verify contacts after resolving with offline recovery."
        }
    }

    private func contactConflictText(_ conflict: ContactAuthorityConflict) -> String {
        switch conflict.kind {
        case .fork:
            "Contact \(conflict.account) presented concurrent device-authority branches in recovery epoch \(conflict.recoveryEpoch). The accepted branch was retained; offline recovery is required."
        case .recovery:
            "Contact \(conflict.account) presented different recoveries for epoch \(conflict.recoveryEpoch). The accepted branch was retained and verification was cleared."
        }
    }
}

private enum DeviceApprovalKind: String, Identifiable {
    case link
    case authority
    var id: String { rawValue }
}

private struct DeviceLinkSourceView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var offer = ""
    @State private var response = ""
    @State private var code: String?
    @State private var contacts = true
    @State private var organization = true
    @State private var history = false
    @State private var confirmed = false
    @State private var package = ""
    @State private var approvalRequest = ""
    @State private var additionalApproval = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Scan this ten-minute offer on a pristine installation. Nothing transfers before both screens show the same six digits.")
                }
                if !offer.isEmpty {
                    Section("Offer") {
                        AnimatedDeviceLinkQr(frames: deviceLinkQrFrames(offer))
                            .frame(height: 280)
                        Text(offer).font(.caption2.monospaced()).textSelection(.enabled)
                        Button("Copy offer") { UIPasteboard.general.string = offer }
                    }
                }
                Section("Response from new device") {
                    TextEditor(text: $response).frame(minHeight: 100).incognitoKeyboard()
                    Button("Show comparison code") { compare() }.disabled(response.isEmpty)
                }
                if let code {
                    Section("Compare on both devices") {
                        Text(code).font(.largeTitle.monospacedDigit()).accessibilityLabel("Comparison code \(code)")
                        Toggle("Contacts and verification", isOn: $contacts)
                        Toggle("Folders, labels, pins, icons, and appearance", isOn: $organization)
                        Toggle("Non-ephemeral history", isOn: $history)
                        Toggle("I compared the six digits", isOn: $confirmed)
                        Button("Approve and create package") { approve() }.disabled(!confirmed)
                    }
                }
                if !package.isEmpty {
                    Section("Encrypted package for new device") {
                        Text(package).font(.caption2.monospaced()).textSelection(.enabled)
                        Button("Copy encrypted package") { UIPasteboard.general.string = package }
                    }
                }
                if !approvalRequest.isEmpty && package.isEmpty {
                    Section("Additional active-device approval") {
                        Text("Transfer this exact add-device proposal to another active installation. Its detached signature cannot alter the proposal.")
                            .font(.footnote)
                        Text(approvalRequest)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                        Button("Copy approval request") {
                            UIPasteboard.general.string = approvalRequest
                        }
                        TextEditor(text: $additionalApproval)
                            .frame(minHeight: 100)
                            .incognitoKeyboard()
                        Button("Accept detached approval", action: acceptAdditionalApproval)
                            .disabled(additionalApproval.isEmpty)
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Link another device")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
            .task {
                do { offer = try await model.beginDeviceLink() }
                catch { self.error = errorText(error) }
            }
        }
    }

    private func compare() {
        Task {
            do { code = try await model.deviceLinkConfirmationCode(responseHex: response) }
            catch { self.error = errorText(error) }
        }
    }

    private func approve() {
        Task {
            do {
                package = try await model.approveDeviceLink(
                    responseHex: response, contacts: contacts,
                    organization: organization, history: history, confirmed: confirmed)
            } catch {
                self.error = errorText(error)
                if self.error?.contains("additional active-device approval") == true {
                    do {
                        approvalRequest = try await model.deviceLinkApprovalRequest()
                    } catch {
                        self.error = errorText(error)
                    }
                }
            }
        }
    }

    private func acceptAdditionalApproval() {
        Task {
            do {
                if let finalized = try await model.acceptDeviceLinkApproval(additionalApproval) {
                    package = finalized
                    approvalRequest = ""
                    additionalApproval = ""
                    error = nil
                } else {
                    error = "Approval accepted; another active device is still required."
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

private struct DeviceLinkTargetView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = "iPhone"
    @State private var offer = ""
    @State private var response = ""
    @State private var code: String?
    @State private var package = ""
    @State private var confirmed = false
    @State private var scanning = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section { Text("Use only on a pristine installation. Scan or paste the source offer.") }
                Section("Offer") {
                    TextField("Name for this device", text: $name)
                        .incognitoKeyboard(capitalization: .words)
                    TextEditor(text: $offer).frame(minHeight: 100).incognitoKeyboard()
                    Button("Scan offer QR") { scanning = true }
                    Button("Accept offer") { accept() }.disabled(name.isEmpty || offer.isEmpty)
                }
                if let code {
                    Section("Compare on both devices") {
                        Text(code).font(.largeTitle.monospacedDigit()).accessibilityLabel("Comparison code \(code)")
                        Text(response).font(.caption2.monospaced()).textSelection(.enabled)
                        Button("Copy response") { UIPasteboard.general.string = response }
                        TextEditor(text: $package).frame(minHeight: 120).incognitoKeyboard()
                        Toggle("I compared the six digits", isOn: $confirmed)
                        Button("Complete device link") { complete() }.disabled(!confirmed || package.isEmpty)
                    }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Link this new device")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            .sheet(isPresented: $scanning) {
                QrScannerView { text in offer = text; scanning = false }
                    .ignoresSafeArea()
            }
        }
    }

    private func accept() {
        Task {
            do {
                let accepted = try await model.acceptDeviceLink(offerHex: offer, name: name)
                response = accepted.0
                code = accepted.1
            } catch { self.error = errorText(error) }
        }
    }

    private func complete() {
        Task {
            do {
                try await model.completeDeviceLink(packageHex: package, confirmed: confirmed)
                dismiss()
            } catch { self.error = errorText(error) }
        }
    }
}

private struct DeviceSyncImportView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var bundle = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Text("Paste an encrypted convergence bundle exported for this exact active device. Replays are rejected.")
                TextEditor(text: $bundle).frame(minHeight: 180).incognitoKeyboard()
                if let error { Text(error).foregroundStyle(.red) }
                Button("Import encrypted sync") { importBundle() }.disabled(bundle.isEmpty)
            }
            .navigationTitle("Import device sync")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }

    private func importBundle() {
        Task {
            do { _ = try await model.importDeviceSync(bundleHex: bundle); dismiss() }
            catch { self.error = errorText(error) }
        }
    }
}

private struct AnimatedDeviceLinkQr: View {
    let frames: [String]

    var body: some View {
        if frames.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "qrcode")
                    .font(.largeTitle)
                Text("Offer cannot be rendered")
                    .font(.headline)
                Text("Use the exact pasted offer instead.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else {
            TimelineView(.periodic(from: .now, by: 1.1)) { context in
                let tick = Int(context.date.timeIntervalSinceReferenceDate / 1.1)
                let index = tick % frames.count
                VStack(spacing: 6) {
                    QrCodeView(text: frames[index])
                    Text(
                        frames.count == 1
                            ? "Device link offer"
                            : "Device link frame \(index + 1) of \(frames.count) · keep the scanner pointed here"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(
                    frames.count == 1
                        ? "Device link offer QR"
                        : "Device link frame \(index + 1) of \(frames.count)")
            }
        }
    }
}

private struct DeviceApprovalView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let kind: DeviceApprovalKind
    @State private var request = ""
    @State private var approval = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Text(
                    kind == .link
                        ? "Verify and sign an exact pending add-device proposal from another active installation."
                        : "Verify and sign an exact pending rename or revocation proposal from another active installation."
                )
                TextEditor(text: $request)
                    .frame(minHeight: 160)
                    .incognitoKeyboard()
                Button("Verify and approve", action: approve)
                    .disabled(request.isEmpty)
                if !approval.isEmpty {
                    Section("Detached approval") {
                        Text(approval)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                        Button("Copy detached approval") {
                            UIPasteboard.general.string = approval
                        }
                    }
                }
                if let error { Text(error).foregroundStyle(ThemePalette.danger) }
            }
            .navigationTitle(
                kind == .link ? "Approve device link" : "Approve device change")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func approve() {
        Task {
            do {
                if kind == .link {
                    approval = try await model.approveDeviceLinkRequest(request)
                } else {
                    approval = try await model.approveDeviceAuthorityRequest(request)
                }
                error = nil
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

private struct PendingDeviceAuthorityView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var request = ""
    @State private var approval = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Text("Transfer this exact pending rename or revocation proposal to another active device, then paste its detached approval.")
                if !request.isEmpty {
                    Text(request)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                    Button("Copy approval request") {
                        UIPasteboard.general.string = request
                    }
                }
                TextEditor(text: $approval)
                    .frame(minHeight: 140)
                    .incognitoKeyboard()
                Button("Accept detached approval", action: accept)
                    .disabled(request.isEmpty || approval.isEmpty)
                if let error { Text(error).foregroundStyle(ThemePalette.danger) }
            }
            .navigationTitle("Continue device change")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .task {
                do {
                    request = try await model.deviceAuthorityApprovalRequest()
                } catch {
                    self.error = errorText(error)
                }
            }
        }
    }

    private func accept() {
        Task {
            do {
                if try await model.acceptDeviceAuthorityApproval(approval) {
                    dismiss()
                } else {
                    error = "Approval accepted; another active device is still required."
                }
            } catch {
                self.error = errorText(error)
            }
        }
    }
}

private extension View {
    func badgeStyle() -> some View {
        self.font(.caption2).padding(.horizontal, 6).padding(.vertical, 2)
            .background(.secondary.opacity(0.18), in: Capsule())
    }
}
