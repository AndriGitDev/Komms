import KommsCore
import SwiftUI

struct ScheduleEditor: Identifiable {
    let id = UUID()
    let message: ScheduledMessage?
    let body: String
    let notBefore: Date

    init(message: ScheduledMessage) {
        self.message = message
        body = message.body
        notBefore = Date(timeIntervalSince1970: TimeInterval(message.notBefore))
    }

    init(body: String) {
        message = nil
        self.body = body
        notBefore = Date().addingTimeInterval(30 * 60)
    }
}

struct ScheduledMessageEditor: View {
    @Environment(\.dismiss) private var dismiss

    let editor: ScheduleEditor
    let save: (String, Date) async throws -> Void

    @State private var messageBody: String
    @State private var notBefore: Date
    @State private var working = false
    @State private var error: String?

    init(editor: ScheduleEditor, save: @escaping (String, Date) async throws -> Void) {
        self.editor = editor
        self.save = save
        _messageBody = State(initialValue: editor.body)
        _notBefore = State(initialValue: editor.notBefore)
    }

    var bodyView: some View {
        NavigationStack {
            Form {
                Section("Message") {
                    TextField("Message", text: $messageBody, axis: .vertical)
                        .lineLimit(2...8)
                        .incognitoKeyboard(capitalization: .sentences)
                }
                Section("Send at") {
                    DatePicker(
                        "Local time", selection: $notBefore,
                        displayedComponents: [.date, .hourAndMinute])
                    Text("Stored as an absolute UTC instant. Time-zone changes do not move it.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle(editor.message == nil ? "Schedule message" : "Edit schedule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(working)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(editor.message == nil ? "Schedule" : "Save") { submit() }
                        .disabled(
                            working
                                || messageBody.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    var body: some View { bodyView }

    private func submit() {
        working = true
        error = nil
        let text = messageBody.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do {
                try await save(text, notBefore)
                dismiss()
            } catch {
                self.error = errorText(error)
                working = false
            }
        }
    }
}

struct ScheduledMessageBubble: View {
    @EnvironmentObject private var model: AppModel
    let message: ScheduledMessage
    let edit: () -> Void
    let cancel: () -> Void

    @State private var confirmCancel = false

    var body: some View {
        HStack {
            Spacer(minLength: 40)
            VStack(alignment: .trailing, spacing: 5) {
                FormattedTextView(formatted: model.formattedText(source: message.body))
                    .padding(10)
                    .background(Color.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 12))
                    .overlay {
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(
                                Color.orange,
                                style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
                    }
                Text(
                    "Scheduled · "
                        + Date(timeIntervalSince1970: TimeInterval(message.notBefore))
                        .formatted(date: .abbreviated, time: .shortened))
                    .font(.caption2)
                    .foregroundStyle(.orange)
                HStack(spacing: 12) {
                    Button("Edit", action: edit)
                    Button("Cancel", role: .destructive) { confirmCancel = true }
                }
                .font(.caption)
            }
        }
        .confirmationDialog(
            "Cancel this scheduled message?",
            isPresented: $confirmCancel,
            titleVisibility: .visible
        ) {
            Button("Cancel message", role: .destructive, action: cancel)
            Button("Keep scheduled", role: .cancel) {}
        }
    }
}
