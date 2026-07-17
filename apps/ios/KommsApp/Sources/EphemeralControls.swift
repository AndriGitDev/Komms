import SwiftUI

enum EphemeralLifetime: UInt64, CaseIterable, Identifiable {
    case minute = 60
    case hour = 3_600
    case day = 86_400
    case week = 604_800
    case month = 2_592_000

    var id: UInt64 { rawValue }

    var label: String {
        switch self {
        case .minute: return "1 minute"
        case .hour: return "1 hour"
        case .day: return "1 day"
        case .week: return "7 days"
        case .month: return "30 days"
        }
    }
}

struct EphemeralTextControl: View {
    @Binding var lifetime: EphemeralLifetime?

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Picker("Remove after", selection: $lifetime) {
                Text("Off").tag(EphemeralLifetime?.none)
                ForEach(EphemeralLifetime.allCases) { value in
                    Text(value.label).tag(Optional(value))
                }
            }
            .pickerStyle(.menu)
            if lifetime != nil {
                Text("Removed from this device at the selected time; recipients and other devices may retain copies.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
