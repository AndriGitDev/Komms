// Shared pairwise/group attachment UI. External documents stay behind iOS's
// security-scoped picker URLs; AppModel stages bounded copies in app-private
// storage, and completed objects leave through a caller-selected export picker.

import KommsCore
import SwiftUI
import UniformTypeIdentifiers
import UIKit

enum AttachmentDestination {
    case peer(String)
    case group(String)
}

struct AttachmentPickerButton: View {
    @EnvironmentObject private var model: AppModel

    let destination: AttachmentDestination
    var disabled = false
    let reportError: (String?) -> Void

    @State private var picking = false
    @State private var working = false

    var body: some View {
        Button {
            picking = true
        } label: {
            if working {
                ProgressView()
            } else {
                Image(systemName: "paperclip").font(.title2)
            }
        }
        .disabled(disabled || working)
        .accessibilityLabel("Attach file")
        .fileImporter(
            isPresented: $picking,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { importDocument(url) }
            case .failure(let error):
                reportError(errorText(error))
            }
        }
    }

    private func importDocument(_ url: URL) {
        working = true
        reportError(nil)
        Task {
            defer { working = false }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let values = try? url.resourceValues(forKeys: [.contentTypeKey])
            let mediaType = values?.contentType?.preferredMIMEType
                ?? "application/octet-stream"
            let filename = url.lastPathComponent.isEmpty ? nil : url.lastPathComponent
            do {
                switch destination {
                case .peer(let peer):
                    try await model.sendAttachment(
                        peer: peer, source: url, mediaType: mediaType, filename: filename)
                case .group(let group):
                    try await model.sendGroupAttachment(
                        group: group, source: url, mediaType: mediaType, filename: filename)
                }
            } catch {
                reportError(errorText(error))
            }
        }
    }
}

struct AttachmentTransferView: View {
    @EnvironmentObject private var model: AppModel

    let attachment: Attachment

    @State private var working = false
    @State private var error: String?
    @State private var exportItem: AttachmentExport?
    @State private var exportDirectory: URL?

    private var primary: AttachmentObject? {
        attachment.objects.first(where: { !$0.preview }) ?? attachment.objects.first
    }

    private var awaitingConsent: Bool {
        attachment.direction == .inbound
            && (attachment.state == .offered || attachment.state == .awaitingConsent)
    }

    private var active: Bool {
        switch attachment.state {
        case .offered, .awaitingConsent, .queued, .transferring, .paused: return true
        case .complete, .rejected, .cancelled, .corrupt, .unavailable: return false
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "doc.fill")
                Text(primary?.filename ?? "attachment").font(.headline)
                Spacer()
                if working { ProgressView().controlSize(.small) }
            }

            Text("\(directionText) · \(stateText(attachment.state))")
                .font(.caption)
                .foregroundStyle(.secondary)

            ForEach(attachment.objects.indices, id: \.self) { index in
                objectProgress(attachment.objects[index])
            }

            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    if awaitingConsent {
                        actionButton("Accept") {
                            try await model.acceptAttachment(transfer: attachment.transferId)
                        }
                        actionButton("Reject", role: .destructive) {
                            try await model.rejectAttachment(transfer: attachment.transferId)
                        }
                    } else {
                        if attachment.state == .paused {
                            actionButton("Resume") {
                                try await model.resumeAttachment(transfer: attachment.transferId)
                            }
                        } else if attachment.state == .offered
                                    || attachment.state == .queued
                                    || attachment.state == .transferring {
                            actionButton("Pause") {
                                try await model.pauseAttachment(transfer: attachment.transferId)
                            }
                        }
                        if active {
                            actionButton("Cancel", role: .destructive) {
                                try await model.cancelAttachment(transfer: attachment.transferId)
                            }
                        }
                    }
                    if attachment.direction == .inbound && attachment.state == .complete {
                        Button("Export…") { prepareExport() }
                            .disabled(working || primary == nil)
                    }
                }
            }
        }
        .padding(12)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .sheet(item: $exportItem, onDismiss: cleanupExport) { item in
            AttachmentExportPicker(file: item.file) { exportItem = nil }
        }
        .onDisappear { cleanupExport() }
    }

    private var directionText: String {
        attachment.direction == .inbound ? "inbound" : "outbound"
    }

    @ViewBuilder
    private func objectProgress(_ object: AttachmentObject) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(object.preview ? "Preview" : "Primary") · \(object.mediaType)")
                .font(.caption)
            ProgressView(
                value: Double(min(object.verifiedBytes, object.totalBytes)),
                total: Double(max(object.totalBytes, 1)))
                .accessibilityLabel("Verified attachment progress")
            Text("\(object.verifiedBytes) / \(object.totalBytes) verified bytes · \(stateText(object.state))")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func actionButton(
        _ title: String,
        role: ButtonRole? = nil,
        action: @escaping () async throws -> Void
    ) -> some View {
        Button(title, role: role) { perform(action) }.disabled(working)
    }

    private func perform(_ action: @escaping () async throws -> Void) {
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                try await action()
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func prepareExport() {
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                let file = try await model.prepareAttachmentExport(
                    transfer: attachment.transferId, filename: primary?.filename)
                exportDirectory = file.deletingLastPathComponent()
                exportItem = AttachmentExport(file: file)
            } catch {
                self.error = errorText(error)
            }
        }
    }

    private func cleanupExport() {
        if let exportDirectory {
            try? FileManager.default.removeItem(at: exportDirectory)
            self.exportDirectory = nil
        }
    }
}

private struct AttachmentExport: Identifiable {
    let file: URL
    var id: String { file.path }
}

private struct AttachmentExportPicker: UIViewControllerRepresentable {
    let file: URL
    let finished: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(finished: finished) }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forExporting: [file], asCopy: true)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let finished: () -> Void

        init(finished: @escaping () -> Void) { self.finished = finished }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            finished()
        }

        func documentPicker(
            _ controller: UIDocumentPickerViewController,
            didPickDocumentsAt urls: [URL]
        ) {
            finished()
        }
    }
}

private func stateText(_ state: AttachmentState) -> String {
    switch state {
    case .offered: return "offered"
    case .awaitingConsent: return "awaiting consent"
    case .queued: return "queued"
    case .transferring: return "transferring"
    case .paused: return "paused"
    case .complete: return "complete"
    case .rejected: return "rejected"
    case .cancelled: return "cancelled"
    case .corrupt: return "integrity check failed"
    case .unavailable: return "unavailable"
    }
}
