import KommsCore
import SwiftUI

/// Private local pin manager. Reorder always submits the complete durable set,
/// including unavailable rows, and stale cleanup stays exact and explicit.
struct PinsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Pinned conversations") {
                    if model.pins.isEmpty {
                        Text("No pinned conversations").foregroundStyle(.secondary)
                    }
                    ForEach(Array(model.pins.enumerated()), id: \.offset) { index, pin in
                        VStack(alignment: .leading) {
                            Text(title(pin))
                            Text("Pin \(index + 1)" + (pin.active ? "" : " · unavailable"))
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Button("Earlier") { model.movePin(pin.target, by: -1) }
                                    .disabled(index == 0)
                                Button("Later") { model.movePin(pin.target, by: 1) }
                                    .disabled(index + 1 == model.pins.count)
                                if pin.active {
                                    Button("Unpin", role: .destructive) { model.togglePin(pin.target) }
                                } else {
                                    Button("Clean up", role: .destructive) {
                                        model.cleanupStalePin(pin.target)
                                    }
                                }
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
                Section {
                    Text("Pins stay sealed on this device. They change presentation order only and create no delivery work.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Pins")
            .toolbar { Button("Done") { dismiss() } }
        }
    }

    private func title(_ pin: Pin) -> String {
        switch pin.target.kind {
        case .noteToSelf: return "Note to self"
        case .peer, .group: return pin.displayName ?? "Unavailable conversation"
        }
    }
}
