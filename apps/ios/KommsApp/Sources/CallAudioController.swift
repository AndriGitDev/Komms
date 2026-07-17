// Foreground-only native audio for authenticated direct-QUIC calls. The
// shared core owns signaling, media authentication, encryption, bounds, and
// jitter; this adapter only converts 48 kHz mono PCM to and from 20 ms Opus.

import AVFoundation
import Foundation
import KommsCore

private let callSampleRate = 48_000.0
private let callFrameCount: AVAudioFrameCount = 960
private let callOpusBitRate = 24_000
private let callMaximumOpusPacket = 1_275

private final class CallCaptureState {
    let resampler: AVAudioConverter
    let encoder: AVAudioConverter
    let pcmFormat: AVAudioFormat
    var samples: [Float] = []

    init(input: AVAudioFormat, pcm: AVAudioFormat, opus: AVAudioFormat) throws {
        guard let resampler = AVAudioConverter(from: input, to: pcm),
              let encoder = AVAudioConverter(from: pcm, to: opus) else {
            throw InputError("this device cannot create the live Opus audio pipeline")
        }
        encoder.bitRate = callOpusBitRate
        self.resampler = resampler
        self.encoder = encoder
        self.pcmFormat = pcm
        samples.reserveCapacity(Int(callFrameCount) * 3)
    }

    func erase() {
        for index in samples.indices { samples[index] = 0 }
        samples.removeAll(keepingCapacity: false)
        resampler.reset()
        encoder.reset()
    }
}

final class CallAudioController {
    typealias Failure = @Sendable (_ call: String, _ reason: String) -> Void

    private let failure: Failure
    private let stateLock = NSLock()
    private let captureQueue = DispatchQueue(label: "komms.call.capture", qos: .userInteractive)
    private let sendQueue = DispatchQueue(label: "komms.call.send", qos: .userInitiated)
    private let playoutQueue = DispatchQueue(label: "komms.call.playout", qos: .userInteractive)
    private var token: UUID?
    private var callId: String?
    private var pendingSends = 0
    private var engine: AVAudioEngine?
    private var player: AVAudioPlayerNode?
    private var captureState: CallCaptureState?
    private var observers: [NSObjectProtocol] = []

    init(failure: @escaping Failure) {
        self.failure = failure
        let center = NotificationCenter.default
        observers.append(center.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: nil, queue: nil
        ) { [weak self] note in
            guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
                  raw == AVAudioSession.InterruptionType.began.rawValue,
                  let call = self?.currentCall() else { return }
            self?.failure(call, "the system interrupted the live audio session")
        })
        observers.append(center.addObserver(
            forName: AVAudioSession.mediaServicesWereResetNotification,
            object: nil, queue: nil
        ) { [weak self] _ in
            guard let call = self?.currentCall() else { return }
            self?.failure(call, "the system audio service restarted")
        })
    }

    deinit { observers.forEach(NotificationCenter.default.removeObserver) }

    func requestPermission() async -> Bool {
        let audio = AVAudioSession.sharedInstance()
        switch audio.recordPermission {
        case .granted:
            return true
        case .denied:
            return false
        case .undetermined:
            return await withCheckedContinuation { continuation in
                audio.requestRecordPermission { continuation.resume(returning: $0) }
            }
        @unknown default:
            return false
        }
    }

    /// Idempotently starts one selected call after explicit mic permission.
    func start(call: String, session: Session) throws {
        stateLock.lock()
        let alreadyRunning = token != nil && callId == call
        stateLock.unlock()
        if alreadyRunning { return }
        stop()

        let audio = AVAudioSession.sharedInstance()
        try audio.setCategory(
            .playAndRecord, mode: .voiceChat,
            options: [.allowBluetooth, .defaultToSpeaker])
        try audio.setPreferredSampleRate(callSampleRate)
        try audio.setPreferredIOBufferDuration(0.02)
        try? audio.setPreferredInputNumberOfChannels(1)
        try? audio.setPreferredOutputNumberOfChannels(1)
        try audio.setActive(true)

        let engine = AVAudioEngine()
        let player = AVAudioPlayerNode()
        let input = engine.inputNode
        try? input.setVoiceProcessingEnabled(true)
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.channelCount > 0,
              let pcm = AVAudioFormat(
                commonFormat: .pcmFormatFloat32,
                sampleRate: callSampleRate,
                channels: 1,
                interleaved: false),
              let opus = AVAudioFormat(settings: [
                AVFormatIDKey: kAudioFormatOpus,
                AVSampleRateKey: callSampleRate,
                AVNumberOfChannelsKey: 1,
                AVEncoderBitRateKey: callOpusBitRate,
              ]) else {
            try? audio.setActive(false, options: .notifyOthersOnDeactivation)
            throw InputError("this device has no usable live audio input or Opus codec")
        }
        let capture = try CallCaptureState(input: inputFormat, pcm: pcm, opus: opus)
        guard let decoder = AVAudioConverter(from: opus, to: pcm) else {
            capture.erase()
            try? audio.setActive(false, options: .notifyOthersOnDeactivation)
            throw InputError("this device cannot decode live Opus audio")
        }

        let token = UUID()
        stateLock.lock()
        self.token = token
        callId = call
        stateLock.unlock()
        self.engine = engine
        self.player = player
        captureState = capture

        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: pcm)
        input.installTap(
            onBus: 0,
            bufferSize: AVAudioFrameCount(max(256, Int(inputFormat.sampleRate * 0.02))),
            format: inputFormat
        ) { [weak self] buffer, _ in
            guard let self else { return }
            self.captureQueue.sync {
                self.encode(
                    buffer: buffer, state: capture, session: session,
                    call: call, token: token, opus: opus)
            }
        }

        do {
            engine.prepare()
            try engine.start()
            player.play()
        } catch {
            stop(call: call)
            throw error
        }
        beginPlayout(
            session: session, call: call, token: token,
            decoder: decoder, opus: opus, pcm: pcm, player: player)
    }

    func stop(call: String? = nil) {
        stateLock.lock()
        if let call, callId != call {
            stateLock.unlock()
            return
        }
        token = nil
        callId = nil
        stateLock.unlock()

        engine?.inputNode.removeTap(onBus: 0)
        engine?.stop()
        player?.stop()
        if let captureState {
            captureQueue.sync { captureState.erase() }
        }
        captureState = nil
        player = nil
        engine = nil
        try? AVAudioSession.sharedInstance().setActive(
            false, options: .notifyOthersOnDeactivation)
    }

    private func isRunning(call: String, token: UUID) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return self.token == token && callId == call
    }

    private func currentCall() -> String? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return token == nil ? nil : callId
    }

    private func encode(
        buffer: AVAudioPCMBuffer,
        state: CallCaptureState,
        session: Session,
        call: String,
        token: UUID,
        opus: AVAudioFormat
    ) {
        guard isRunning(call: call, token: token) else { return }
        let ratio = callSampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount(ceil(Double(buffer.frameLength) * ratio)) + 32
        guard let converted = AVAudioPCMBuffer(
            pcmFormat: state.pcmFormat, frameCapacity: capacity) else { return }
        var supplied = false
        var conversionError: NSError?
        _ = state.resampler.convert(to: converted, error: &conversionError) {
            _, inputStatus in
            if supplied {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied = true
            inputStatus.pointee = .haveData
            return buffer
        }
        guard conversionError == nil, converted.frameLength > 0,
              let channel = converted.floatChannelData?[0] else { return }
        state.samples.append(contentsOf: UnsafeBufferPointer(
            start: channel, count: Int(converted.frameLength)))

        while state.samples.count >= Int(callFrameCount) && isRunning(call: call, token: token) {
            guard let frame = AVAudioPCMBuffer(
                pcmFormat: state.pcmFormat, frameCapacity: callFrameCount),
                let destination = frame.floatChannelData?[0] else { return }
            frame.frameLength = callFrameCount
            for index in 0..<Int(callFrameCount) { destination[index] = state.samples[index] }
            for index in 0..<Int(callFrameCount) { state.samples[index] = 0 }
            state.samples.removeFirst(Int(callFrameCount))
            if var packet = encodeFrame(frame, converter: state.encoder, format: opus) {
                enqueue(packet: packet, session: session, call: call, token: token)
                packet.resetBytes(in: packet.startIndex..<packet.endIndex)
            }
            memset(destination, 0, Int(callFrameCount) * MemoryLayout<Float>.size)
        }
    }

    private func encodeFrame(
        _ frame: AVAudioPCMBuffer,
        converter: AVAudioConverter,
        format: AVAudioFormat
    ) -> Data? {
        let output = AVAudioCompressedBuffer(
            format: format, packetCapacity: 1,
            maximumPacketSize: callMaximumOpusPacket)
        var supplied = false
        var conversionError: NSError?
        _ = converter.convert(to: output, error: &conversionError) { _, inputStatus in
            if supplied {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied = true
            inputStatus.pointee = .haveData
            return frame
        }
        guard conversionError == nil, output.packetCount == 1,
              output.byteLength > 0,
              Int(output.byteLength) <= callMaximumOpusPacket else { return nil }
        return Data(bytes: output.data, count: Int(output.byteLength))
    }

    private func enqueue(
        packet: Data, session: Session, call: String, token: UUID
    ) {
        stateLock.lock()
        guard self.token == token, callId == call, pendingSends < 4 else {
            stateLock.unlock()
            return
        }
        pendingSends += 1
        stateLock.unlock()
        let timestamp = DispatchTime.now().uptimeNanoseconds / 1_000_000
        sendQueue.async { [weak self] in
            var secret = packet
            defer {
                secret.resetBytes(in: secret.startIndex..<secret.endIndex)
                if let self {
                    self.stateLock.lock()
                    self.pendingSends -= 1
                    self.stateLock.unlock()
                }
            }
            guard self?.isRunning(call: call, token: token) == true else { return }
            _ = try? session.sendCallAudio(
                call: call, timestampMs: timestamp, opusPacket: secret)
        }
    }

    private func beginPlayout(
        session: Session,
        call: String,
        token: UUID,
        decoder: AVAudioConverter,
        opus: AVAudioFormat,
        pcm: AVAudioFormat,
        player: AVAudioPlayerNode
    ) {
        playoutQueue.async { [weak self] in
            while self?.isRunning(call: call, token: token) == true {
                var failed = false
                autoreleasepool {
                    let frame: CallAudioFrame
                    do {
                        guard let received = try session.takeCallAudio(call: call) else {
                            Thread.sleep(forTimeInterval: 0.01)
                            return
                        }
                        frame = received
                    } catch {
                        self?.failure(call, error.localizedDescription)
                        failed = true
                        return
                    }
                    var packet = frame.opusPacket
                    defer { packet.resetBytes(in: packet.startIndex..<packet.endIndex) }
                    guard let decoded = self?.decode(
                        packet: packet, converter: decoder, opus: opus, pcm: pcm),
                        decoded.frameLength > 0 else { return }
                    player.scheduleBuffer(decoded)
                }
                if failed { break }
            }
            decoder.reset()
        }
    }

    private func decode(
        packet: Data,
        converter: AVAudioConverter,
        opus: AVAudioFormat,
        pcm: AVAudioFormat
    ) -> AVAudioPCMBuffer? {
        guard !packet.isEmpty, packet.count <= callMaximumOpusPacket,
              let output = AVAudioPCMBuffer(
                pcmFormat: pcm, frameCapacity: callFrameCount) else { return nil }
        let input = AVAudioCompressedBuffer(
            format: opus, packetCapacity: 1,
            maximumPacketSize: callMaximumOpusPacket)
        packet.withUnsafeBytes { bytes in
            if let base = bytes.baseAddress { memcpy(input.data, base, packet.count) }
        }
        input.byteLength = UInt32(packet.count)
        input.packetCount = 1
        input.packetDescriptions?.pointee = AudioStreamPacketDescription(
            mStartOffset: 0,
            mVariableFramesInPacket: callFrameCount,
            mDataByteSize: UInt32(packet.count))
        var supplied = false
        var conversionError: NSError?
        _ = converter.convert(to: output, error: &conversionError) { _, inputStatus in
            if supplied {
                inputStatus.pointee = .noDataNow
                return nil
            }
            supplied = true
            inputStatus.pointee = .haveData
            return input
        }
        return conversionError == nil ? output : nil
    }
}
