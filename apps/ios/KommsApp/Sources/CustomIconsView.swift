import KommsCore
import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct CustomIconAvatar: View {
    @EnvironmentObject private var model: AppModel
    let target: CustomIconTarget
    let label: String
    var size: CGFloat = 42

    var body: some View {
        Group {
            if let icon = model.customIcon(for: target), let image = UIImage(data: icon.bytes) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                Circle()
                    .fill(.tint)
                    .overlay(Text(initials(label)).font(.system(size: size * 0.34, weight: .semibold)).foregroundStyle(.white))
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .accessibilityHidden(true)
    }
}

struct CustomIconsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var selectedID = "note_to_self:"
    @State private var importing = false
    @State private var working = false
    @State private var error: String?
    @State private var result = ""

    private let glyphs = ["person", "group", "folder", "note", "star", "heart", "shield", "compass"]

    private var choices: [IconChoice] {
        [IconChoice(target: .init(kind: .noteToSelf, id: nil), label: "Note to self")] +
        model.contacts.map { IconChoice(target: .init(kind: .contact, id: $0.peer), label: "Contact · \($0.name)") } +
        model.groups.map { IconChoice(target: .init(kind: .group, id: $0.id), label: "Group · \($0.name)") } +
        model.folders.map { IconChoice(target: .init(kind: .folder, id: $0.id), label: "Folder \($0.order + 1) · \($0.name)") }
    }

    private var selected: IconChoice {
        choices.first(where: { $0.id == selectedID }) ?? choices[0]
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Icons stay sealed on this device. Selected JPEG/PNG files are cropped, resized to 256×256, and re-encoded without metadata. Icons are never fetched from URLs or sent to peers.")
                        .font(.footnote)
                }
                Section("Local target") {
                    Picker("Target", selection: $selectedID) {
                        ForEach(choices) { Text(verbatim: $0.label).tag($0.id) }
                    }
                    HStack {
                        Spacer()
                        CustomIconAvatar(target: selected.target, label: selected.label, size: 96)
                        Spacer()
                    }
                    if let icon = model.customIcon(for: selected.target) {
                        Text("Private local icon · \(icon.bytes.count.formatted()) encoded bytes")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Generated initials fallback")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("Bundled glyph") {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 4)) {
                        ForEach(glyphs, id: \.self) { glyph in
                            Button(glyph.capitalized) { setGlyph(glyph) }
                                .disabled(working)
                                .accessibilityLabel("Use bundled \(glyph) glyph")
                        }
                    }
                }
                Section {
                    Button("Choose local image…") { importing = true }
                        .disabled(working)
                    Button("Use generated initials", role: .destructive) { clear() }
                        .disabled(working || model.customIcon(for: selected.target) == nil)
                    Text("\(model.customIconUsage.records.formatted()) / 1,024 icons · \(model.customIconUsage.bytes.formatted()) / 67,108,864 bytes")
                        .font(.caption).foregroundStyle(.secondary)
                    if let error { Text(error).foregroundStyle(.red).accessibilityLabel("Error: \(error)") }
                    if result.isEmpty == false { Text(result).font(.footnote).accessibilityLabel(result) }
                }
            }
            .navigationTitle("Private custom icons")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .fileImporter(
                isPresented: $importing,
                allowedContentTypes: [.jpeg, .png],
                allowsMultipleSelection: false
            ) { response in
                switch response {
                case .success(let urls): if let url = urls.first { setImage(url) }
                case .failure(let failure): error = errorText(failure)
                }
            }
        }
    }

    private func setGlyph(_ glyph: String) {
        working = true; error = nil; result = ""
        let target = selected.target
        Task {
            do {
                try await model.setCustomIcon(target: target, glyph: glyph)
                result = "Bundled \(glyph) icon saved locally."
            } catch { self.error = errorText(error) }
            working = false
        }
    }

    private func setImage(_ url: URL) {
        working = true; error = nil; result = ""
        let target = selected.target
        Task {
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            do {
                try await model.setCustomIcon(target: target, source: url)
                result = "Selected image cropped, sanitized, and sealed locally."
            } catch { self.error = errorText(error) }
            working = false
        }
    }

    private func clear() {
        working = true; error = nil; result = ""
        let target = selected.target
        Task {
            do {
                try await model.clearCustomIcon(target: target)
                result = "Generated initials restored."
            } catch { self.error = errorText(error) }
            working = false
        }
    }
}

private struct IconChoice: Identifiable {
    let target: CustomIconTarget
    let label: String
    var id: String {
        let kind = switch target.kind {
        case .contact: "contact"
        case .group: "group"
        case .folder: "folder"
        case .noteToSelf: "note_to_self"
        }
        return "\(kind):\(target.id ?? "")"
    }
}

private func initials(_ label: String) -> String {
    let words = label.split(whereSeparator: \.isWhitespace)
    guard let first = words.first?.first else { return "?" }
    var value = String(first)
    if words.count > 1, let last = words.last?.first { value.append(last) }
    return value.uppercased()
}
