// Shared pairwise/group attachment UI. External documents stay behind iOS's
// security-scoped picker URLs; AppModel stages bounded copies in app-private
// storage, and completed objects leave through a caller-selected export picker.

import KommsCore
import SwiftUI
import UniformTypeIdentifiers
import UIKit
import AVFoundation

enum RecordedAudioDestination: Sendable {
    case peer(String)
    case group(String)
}

struct ProtectedAudio: Identifiable {
    let file: URL
    let info: AudioInfo
    var id: String { file.path }

    func remove() { try? FileManager.default.removeItem(at: file) }
}

@MainActor
final class AudioRecorderModel: NSObject, ObservableObject, AVAudioRecorderDelegate {
    @Published private(set) var isRecording = false
    @Published private(set) var elapsed = 0
    @Published private(set) var status = ""
    @Published private(set) var reviewSource: URL?

    private var recorder: AVAudioRecorder?
    private var timer: Timer?
    private var reviewOnFinish = false
    private var observers: [NSObjectProtocol] = []

    override init() {
        super.init()
        let center = NotificationCenter.default
        for name in [
            UIApplication.didEnterBackgroundNotification,
            UIApplication.protectedDataWillBecomeUnavailableNotification,
            AVAudioSession.interruptionNotification,
            AVAudioSession.routeChangeNotification,
        ] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) {
                [weak self] _ in self?.discard(reason: "Recording interrupted and discarded.")
            })
        }
    }

    deinit {
        observers.forEach(NotificationCenter.default.removeObserver)
        timer?.invalidate()
        recorder?.stop()
        try? AVAudioSession.sharedInstance().setActive(false)
    }

    func toggle() async throws {
        if isRecording { stopForReview(); return }
        let allowed = await withCheckedContinuation { continuation in
            AVAudioSession.sharedInstance().requestRecordPermission {
                continuation.resume(returning: $0)
            }
        }
        guard allowed else {
            status = "Microphone permission was denied; the composer remains available."
            throw InputError(status)
        }
        try start()
    }

    private func start() throws {
        discardReview()
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(
            .playAndRecord, mode: .spokenAudio,
            options: [.defaultToSpeaker, .allowBluetooth])
        try session.setActive(true)
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-audio-\(UUID().uuidString).native.wav")
        let settings: [String: Any] = [
            AVFormatIDKey: kAudioFormatLinearPCM,
            AVSampleRateKey: 16_000,
            AVNumberOfChannelsKey: 1,
            AVLinearPCMBitDepthKey: 16,
            AVLinearPCMIsBigEndianKey: false,
            AVLinearPCMIsFloatKey: false,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue,
        ]
        do {
            let recorder = try AVAudioRecorder(url: source, settings: settings)
            recorder.delegate = self
            guard recorder.prepareToRecord() else {
                throw InputError("microphone could not prepare")
            }
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete], ofItemAtPath: source.path)
            guard recorder.record(forDuration: 60) else {
                throw InputError("microphone could not start")
            }
            self.recorder = recorder
        } catch {
            try? FileManager.default.removeItem(at: source)
            try? session.setActive(false, options: .notifyOthersOnDeactivation)
            throw error
        }
        isRecording = true
        reviewOnFinish = true
        elapsed = 0
        status = "Recording audio. Stop to review; it is not sent yet."
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.elapsed = min(60, Int(self.recorder?.currentTime ?? 0))
            self.status = "Recording audio, \(self.elapsed) seconds elapsed."
        }
    }

    func stopForReview() {
        guard isRecording else { return }
        reviewOnFinish = true
        recorder?.stop()
    }

    func discard(reason: String = "Audio recording discarded.") {
        guard recorder != nil || reviewSource != nil else { return }
        reviewOnFinish = false
        let source = recorder?.url
        recorder?.stop()
        source.map { try? FileManager.default.removeItem(at: $0) }
        discardReview()
        status = reason
    }

    func consumeReviewSource() -> URL? {
        defer { reviewSource = nil }
        return reviewSource
    }

    func discardReview() {
        reviewSource.map { try? FileManager.default.removeItem(at: $0) }
        reviewSource = nil
    }

    func audioRecorderDidFinishRecording(_ recorder: AVAudioRecorder, successfully flag: Bool) {
        timer?.invalidate()
        timer = nil
        self.recorder = nil
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        if flag && reviewOnFinish {
            reviewSource = recorder.url
            status = elapsed >= 60
                ? "Maximum duration reached. Review before sending."
                : "Recording stopped. Review before sending or discarding."
        } else {
            try? FileManager.default.removeItem(at: recorder.url)
            status = "Audio recording discarded."
        }
        reviewOnFinish = false
    }
}

@MainActor
final class ProtectedAudioPlayer: NSObject, ObservableObject, AVAudioPlayerDelegate {
    @Published var playing = false
    @Published var position = 0.0
    private var player: AVAudioPlayer?
    private var timer: Timer?

    func toggle(file: URL) throws {
        if player == nil {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .spokenAudio)
            try session.setActive(true)
            player = try AVAudioPlayer(contentsOf: file)
            player?.delegate = self
            player?.prepareToPlay()
        }
        guard let player else { return }
        if player.isPlaying {
            player.pause(); playing = false; timer?.invalidate()
        } else {
            player.play(); playing = true
            timer?.invalidate()
            timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) {
                [weak self] _ in self?.position = player.currentTime
            }
        }
    }

    func seek(_ value: Double) {
        player?.currentTime = value
        position = value
    }

    func stop() {
        timer?.invalidate(); timer = nil
        player?.stop(); player = nil
        playing = false; position = 0
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        stop()
    }
}

struct AudioWaveform: View {
    let peaks: [UInt16]

    var body: some View {
        GeometryReader { geometry in
            let maximum = max(1, Int(peaks.max() ?? 1))
            HStack(alignment: .center, spacing: 1) {
                ForEach(peaks.indices, id: \.self) { index in
                    Capsule()
                        .frame(
                            width: max(1, geometry.size.width / CGFloat(peaks.count) - 1),
                            height: max(2, geometry.size.height * CGFloat(peaks[index]) / CGFloat(maximum)))
                }
            }
            .frame(maxHeight: .infinity, alignment: .center)
        }
        .frame(height: 42)
        .foregroundStyle(Color.accentColor)
        .accessibilityElement()
        .accessibilityLabel("Locally derived audio waveform")
    }
}

struct ProtectedAudioView: View {
    let audio: ProtectedAudio
    @StateObject private var player = ProtectedAudioPlayer()
    @State private var error: String?

    private var seconds: Double { Double(audio.info.durationMs) / 1_000 }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(duration(audio.info.durationMs)) · mono PCM WAV · 16 kHz")
                .font(.caption).foregroundStyle(.secondary)
            AudioWaveform(peaks: audio.info.waveform)
            Slider(
                value: Binding(get: { player.position }, set: { player.seek($0) }),
                in: 0...max(seconds, 0.001))
                .accessibilityLabel("Audio playback position")
            Button(player.playing ? "Pause" : "Play") {
                do { try player.toggle(file: audio.file) }
                catch { self.error = errorText(error) }
            }
            .accessibilityHint("Playback never starts automatically")
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
        .onDisappear { player.stop() }
    }
}

struct AudioComposerButton: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    let destination: RecordedAudioDestination
    let reportError: (String?) -> Void

    @StateObject private var recorder = AudioRecorderModel()
    @State private var review: ProtectedAudio?
    @State private var carrier = ""
    @State private var carrierSnapshot = ""
    @State private var preparing = false
    @State private var visible = false

    var body: some View {
        Button {
            Task {
                do { try await recorder.toggle() }
                catch { reportError(errorText(error)) }
            }
        } label: {
            Image(systemName: recorder.isRecording ? "stop.circle.fill" : "mic.circle")
                .font(.title2)
                .foregroundStyle(recorder.isRecording ? .red : .primary)
        }
        .disabled(preparing)
        .accessibilityLabel(
            recorder.isRecording ? "Stop recording and review" : "Record audio message")
        .accessibilityValue(recorder.isRecording ? "\(recorder.elapsed) seconds elapsed" : "")
        .onChange(of: recorder.reviewSource) { source in
            guard source != nil, let source = recorder.consumeReviewSource() else { return }
            preparing = true
            Task {
                defer { preparing = false }
                var prepared: ProtectedAudio?
                do {
                    async let audio = model.prepareAudioReview(source: source)
                    async let explanation = model.audioCarrierExplanation(destination: destination)
                    prepared = try await audio
                    let currentCarrier = try await explanation
                    guard let prepared, visible, scenePhase == .active else {
                        prepared?.remove()
                        return
                    }
                    review = prepared
                    carrier = currentCarrier
                    carrierSnapshot = currentCarrier
                    reportError(nil)
                } catch {
                    prepared?.remove()
                    try? FileManager.default.removeItem(at: source)
                    reportError(errorText(error))
                }
            }
        }
        .sheet(item: $review, onDismiss: discardReview) { audio in
            NavigationStack {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Review this recording before explicitly sending it. It will never play automatically.")
                    ProtectedAudioView(audio: audio)
                    Text(carrier).font(.footnote).foregroundStyle(.secondary)
                    Spacer()
                    HStack {
                        Button("Discard", role: .destructive) {
                            discardReview(); review = nil
                        }
                        Spacer()
                        Button("Send audio") { send(audio) }.buttonStyle(.borderedProminent)
                    }
                }
                .padding()
                .navigationTitle("Review audio message")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
        .onAppear { visible = true }
        .onDisappear {
            visible = false
            recorder.discard(reason: "Recording discarded because Komms left the foreground.")
            discardReview()
        }
        .onChange(of: scenePhase) { phase in
            guard phase != .active else { return }
            recorder.discard(reason: "Recording interrupted and discarded.")
            discardReview()
            review = nil
        }
    }

    private func send(_ audio: ProtectedAudio) {
        preparing = true
        Task {
            defer { preparing = false }
            do {
                let latestCarrier = try await model.audioCarrierExplanation(destination: destination)
                guard latestCarrier == carrierSnapshot else {
                    carrierSnapshot = latestCarrier
                    carrier = latestCarrier
                        + "\nCarrier state changed. Review the updated explanation, then choose Send audio again."
                    return
                }
                try await model.sendRecordedAudio(destination: destination, audio: audio)
                review = nil
            } catch {
                reportError(errorText(error))
            }
        }
    }

    private func discardReview() {
        review?.remove()
        review = nil
    }
}

private func duration(_ milliseconds: UInt64) -> String {
    let seconds = milliseconds / 1_000
    let remainder = String(seconds % 60)
    let paddedRemainder = String(repeating: "0", count: max(0, 2 - remainder.count)) + remainder
    return "\(seconds / 60):\(paddedRemainder)"
}

enum AttachmentDestination {
    case peer(String)
    case group(String)
}

struct AttachmentPickerButton: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    let destination: AttachmentDestination
    var disabled = false
    let reportError: (String?) -> Void

    @State private var picking = false
    @State private var working = false
    @State private var review: PreparedAttachment?

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
        .sheet(item: $review) { prepared in
            AttachmentReviewSheet(
                destination: destination,
                initial: prepared,
                reportError: reportError)
                .environmentObject(model)
        }
        .onChange(of: scenePhase) { phase in
            guard phase != .active else { return }
            review?.remove()
            review = nil
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
                review = try await model.prepareAttachment(
                    source: url, mediaType: mediaType, filename: filename)
            } catch {
                reportError(errorText(error))
            }
        }
    }
}

private struct AttachmentReviewSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    let destination: AttachmentDestination
    let reportError: (String?) -> Void

    @State private var prepared: PreparedAttachment
    @State private var carrier = "Loading current carrier policy…"
    @State private var carrierSnapshot = ""
    @State private var busy = false
    @State private var localError: String?
    @State private var history: [LocalImageRecipe] = []
    @State private var cropPreset = "Original"
    @State private var cropX = "0"
    @State private var cropY = "0"
    @State private var cropWidth = "1"
    @State private var cropHeight = "1"
    @State private var regionKind = LocalImageRegionKind.blur
    @State private var regionX = "0"
    @State private var regionY = "0"
    @State private var regionWidth = "32"
    @State private var regionHeight = "32"
    @State private var regionStrength = "8"
    @State private var filename: String

    init(
        destination: AttachmentDestination,
        initial: PreparedAttachment,
        reportError: @escaping (String?) -> Void
    ) {
        self.destination = destination
        self.reportError = reportError
        _prepared = State(initialValue: initial)
        switch initial.kind {
        case .image(let image):
            _cropWidth = State(initialValue: String(image.orientedWidth))
            _cropHeight = State(initialValue: String(image.orientedHeight))
            _regionWidth = State(initialValue: String(min(64, image.width)))
            _regionHeight = State(initialValue: String(min(64, image.height)))
            _filename = State(initialValue: image.filename)
        case .generic(let file):
            _filename = State(initialValue: file.filename)
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                switch prepared.kind {
                case .generic(let file): genericReview(file)
                case .image(let image): imageEditor(image)
                }
                Section("Current carrier policy") {
                    Text(carrier)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Current attachment carrier policy: \(carrier)")
                }
                if let localError {
                    Text(localError).foregroundStyle(.red)
                        .accessibilityLabel("Attachment error: \(localError)")
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Discard", role: .destructive) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(sendLabel) { send() }
                        .disabled(busy || carrierSnapshot.isEmpty)
                }
            }
        }
        .task { await loadCarrier() }
        .onDisappear { prepared.remove() }
        .onChange(of: scenePhase) { phase in
            if phase != .active { dismiss() }
        }
    }

    private var title: String {
        if case .image = prepared.kind { return "Edit and review image" }
        return "Review attachment"
    }

    private var sendLabel: String {
        if case .image = prepared.kind { return "Send exact final" }
        return "Send attachment"
    }

    @ViewBuilder
    private func genericReview(_ file: PreparedFile) -> some View {
        Section("Exact file") {
            TextField("Display filename", text: $filename)
            LabeledContent("Type", value: file.mediaType)
            Text("The security-scoped source was copied into protected app-private storage. It is deleted after send or discard.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func imageEditor(_ image: PreparedImage) -> some View {
        Section("Exact final review") {
            if let uiImage = UIImage(contentsOfFile: image.finalAsset.path) {
                Image(uiImage: uiImage)
                    .resizable()
                    .scaledToFit()
                    .accessibilityLabel("Exact final edited image review")
            } else {
                Label("Preview unavailable", systemImage: "photo")
            }
            Text("\(image.width) × \(image.height) pixels · \(image.encodedBytes) bytes · exact metadata-free PNG")
                .font(.footnote).foregroundStyle(.secondary)
            TextField("Display filename", text: $filename)
        }
        Section("Crop in oriented pixels") {
            Picker("Crop preset", selection: $cropPreset) {
                ForEach(["Original", "Free", "Square 1:1", "4:3", "16:9"], id: \.self) {
                    Text($0)
                }
            }
            integerField("Crop X", text: $cropX)
            integerField("Crop Y", text: $cropY)
            integerField("Crop width", text: $cropWidth)
            integerField("Crop height", text: $cropHeight)
            Button("Apply crop") { applyCrop(image) }
        }
        Section("Rotation") {
            HStack {
                Button("Rotate left") { rotate(image, delta: 3) }
                    .accessibilityLabel("Rotate 90 degrees counter-clockwise")
                Spacer()
                Button("Rotate right") { rotate(image, delta: 1) }
                    .accessibilityLabel("Rotate 90 degrees clockwise")
            }
        }
        Section("Manual privacy region") {
            Picker("Operation", selection: $regionKind) {
                ForEach(LocalImageRegionKind.allCases, id: \.self) {
                    Text($0.rawValue.capitalized)
                }
            }
            integerField("Region X", text: $regionX)
            integerField("Region Y", text: $regionY)
            integerField("Region width", text: $regionWidth)
            integerField("Region height", text: $regionHeight)
            integerField("Strength", text: $regionStrength)
            Button("Add privacy region") { addRegion(image) }
            ForEach(image.recipe.regions) { region in
                HStack {
                    Text("\(region.kind.rawValue), x \(region.x), y \(region.y), \(region.width) × \(region.height), strength \(region.strength)")
                    Spacer()
                    Button("Remove", role: .destructive) {
                        var recipe = image.recipe
                        recipe.regions.removeAll { $0.id == region.id }
                        update(image, recipe: recipe)
                    }
                    .accessibilityLabel("Remove \(region.kind.rawValue) region")
                }
            }
        }
        Section("Edit history") {
            HStack {
                Button("Undo") {
                    guard let recipe = history.popLast() else { return }
                    update(image, recipe: recipe, remember: false)
                }.disabled(history.isEmpty)
                Spacer()
                Button("Reset") { update(image, recipe: LocalImageRecipe()) }
            }
            Text("Edits stay on this device. The original is never sent.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    private func integerField(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text).keyboardType(.numberPad)
            .accessibilityLabel(title)
    }

    private func integer(_ value: String, _ name: String) throws -> UInt32 {
        guard let parsed = UInt32(value) else { throw InputError("\(name) must be a whole number") }
        return parsed
    }

    private func centeredCrop(_ image: PreparedImage, wide: UInt32, high: UInt32) -> LocalImageCrop {
        var width = image.orientedWidth
        var height = UInt32(UInt64(width) * UInt64(high) / UInt64(wide))
        if height > image.orientedHeight {
            height = image.orientedHeight
            width = UInt32(UInt64(height) * UInt64(wide) / UInt64(high))
        }
        return LocalImageCrop(
            x: (image.orientedWidth - width) / 2,
            y: (image.orientedHeight - height) / 2,
            width: width, height: height)
    }

    private func applyCrop(_ image: PreparedImage) {
        do {
            var recipe = image.recipe
            switch cropPreset {
            case "Original": recipe.crop = nil
            case "Square 1:1": recipe.crop = centeredCrop(image, wide: 1, high: 1)
            case "4:3": recipe.crop = centeredCrop(image, wide: 4, high: 3)
            case "16:9": recipe.crop = centeredCrop(image, wide: 16, high: 9)
            default:
                recipe.crop = LocalImageCrop(
                    x: try integer(cropX, "crop X"), y: try integer(cropY, "crop Y"),
                    width: try integer(cropWidth, "crop width"),
                    height: try integer(cropHeight, "crop height"))
            }
            update(image, recipe: recipe)
        } catch { localError = errorText(error) }
    }

    private func rotate(_ image: PreparedImage, delta: UInt8) {
        var recipe = image.recipe
        recipe.rotation = (recipe.rotation + delta) % 4
        recipe.regions = []
        update(image, recipe: recipe)
    }

    private func addRegion(_ image: PreparedImage) {
        do {
            var recipe = image.recipe
            recipe.regions.append(LocalImageRegion(
                kind: regionKind,
                x: try integer(regionX, "region X"), y: try integer(regionY, "region Y"),
                width: try integer(regionWidth, "region width"),
                height: try integer(regionHeight, "region height"),
                strength: try integer(regionStrength, "strength")))
            update(image, recipe: recipe)
        } catch { localError = errorText(error) }
    }

    private func update(
        _ image: PreparedImage, recipe: LocalImageRecipe, remember: Bool = true
    ) {
        busy = true
        localError = nil
        Task {
            do {
                let updated = try await model.updatePreparedImage(image, recipe: recipe)
                if remember { history.append(image.recipe) }
                try? FileManager.default.removeItem(at: image.finalAsset)
                prepared.kind = .image(updated)
            } catch {
                prepared.remove()
                localError = errorText(error)
                reportError(localError)
                dismiss()
            }
            busy = false
        }
    }

    private func loadCarrier() async {
        do {
            let explanation = try await model.attachmentCarrierExplanation(destination: destination)
            carrier = explanation
            carrierSnapshot = explanation
        } catch {
            localError = errorText(error)
        }
    }

    private func send() {
        busy = true
        localError = nil
        if case .image(var image) = prepared.kind {
            image.filename = filename.isEmpty ? "edited-image.png" : filename
            prepared.kind = .image(image)
        } else if case .generic(var file) = prepared.kind {
            file.filename = filename.isEmpty ? "attachment" : filename
            prepared.kind = .generic(file)
        }
        Task {
            do {
                try await model.sendPreparedAttachment(
                    destination: destination, prepared: prepared,
                    expectedCarrier: carrierSnapshot)
                dismiss()
            } catch {
                let message = errorText(error)
                if message.hasPrefix("carrier_changed:") {
                    let changed = String(message.dropFirst("carrier_changed:".count))
                    carrier = changed
                    carrierSnapshot = changed
                    localError = "Carrier state changed. Review the updated explanation, then confirm again."
                    busy = false
                } else {
                    prepared.remove()
                    reportError(message)
                    dismiss()
                }
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
    @State private var previewImage: UIImage?
    @State private var protectedAudio: ProtectedAudio?

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
                Image(systemName: mediaIcon)
                Text(primary?.mediaType == "audio/wav" ? "Audio message" : (primary?.filename ?? "attachment"))
                    .font(.headline)
                Spacer()
                if working { ProgressView().controlSize(.small) }
            }

            Text("\(directionText) · \(stateText(attachment.state))")
                .font(.caption)
                .foregroundStyle(.secondary)

            if let previewImage {
                Image(uiImage: previewImage)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity, maxHeight: 220)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .accessibilityLabel("Local attachment preview")
            }

            if let protectedAudio {
                ProtectedAudioView(audio: protectedAudio)
            } else if primary?.mediaType == "audio/wav" && attachment.state == .complete {
                ProgressView("Preparing protected audio playback…")
            }

            Text("iOS transfers continue only while the system allows background execution; verified progress resumes when Komms returns to the foreground.")
                .font(.caption2)
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
        .task(id: previewTaskKey) { await loadPreview() }
        .task(id: audioTaskKey) { await loadAudio() }
        .onDisappear {
            cleanupExport()
            protectedAudio?.remove()
            protectedAudio = nil
        }
    }

    private var directionText: String {
        attachment.direction == .inbound ? "inbound" : "outbound"
    }

    private var mediaIcon: String {
        let mediaType = primary?.mediaType ?? ""
        if mediaType.hasPrefix("image/") { return "photo.fill" }
        if mediaType.hasPrefix("video/") { return "video.fill" }
        if mediaType.hasPrefix("audio/") { return "waveform" }
        return "doc.fill"
    }

    private var previewTaskKey: String {
        let sealed = attachment.objects.contains { $0.preview && $0.state == .complete }
        let canonical = primary?.mediaType == "image/png" && attachment.state == .complete
        return "\(attachment.transferId):\(sealed):\(canonical)"
    }

    private var audioTaskKey: String {
        "\(attachment.transferId):\(primary?.mediaType ?? ""):\(attachment.state == .complete)"
    }

    private func loadAudio() async {
        guard primary?.mediaType == "audio/wav", attachment.state == .complete else {
            protectedAudio?.remove()
            protectedAudio = nil
            return
        }
        do {
            protectedAudio?.remove()
            protectedAudio = try await model.attachmentAudio(transfer: attachment.transferId)
        } catch {
            self.error = errorText(error)
        }
    }

    private func loadPreview() async {
        let sealed = attachment.objects.contains { $0.preview && $0.state == .complete }
        let canonical = primary?.mediaType == "image/png" && attachment.state == .complete
        guard sealed || canonical else {
            previewImage = nil
            return
        }
        do {
            let data: Data
            if sealed {
                data = try await model.attachmentPreview(transfer: attachment.transferId)
            } else {
                data = try await model.attachmentImage(transfer: attachment.transferId)
            }
            previewImage = UIImage(data: data)
        } catch {
            previewImage = nil
        }
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
