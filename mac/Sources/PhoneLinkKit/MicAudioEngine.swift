import Foundation
#if canImport(AVFoundation)
import AVFoundation
#endif

/// Writes little-endian signed 16-bit PCM audio into a valid RIFF/WAVE container,
/// updating header sizes atomically upon finalization (including early interrupts).
public final class MicWavWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let fileURL: URL
    private let sampleRateHz: UInt32
    private let channels: UInt16
    private let bitsPerSample: UInt16
    private var fileHandle: FileHandle?
    private var dataBytesWritten: UInt64 = 0
    private var isFinalized = false
    public private(set) var lastFinalizeError: String? = nil

    public static func buildWavHeader(
        sampleRateHz: UInt32,
        channels: UInt16,
        bitsPerSample: UInt16,
        dataSizeBytes: UInt32
    ) -> Data {
        var header = Data(capacity: 44)
        func appendLE32(_ v: UInt32) {
            var le = v.littleEndian
            header.append(Data(bytes: &le, count: 4))
        }
        func appendLE16(_ v: UInt16) {
            var le = v.littleEndian
            header.append(Data(bytes: &le, count: 2))
        }

        let safeChannels = max(1, min(8, channels))
        let safeBits: UInt16 = bitsPerSample == 8 ? 8 : 16
        let blockAlign = safeChannels &* (safeBits / 8)
        let byteRate = sampleRateHz &* UInt32(blockAlign)
        let riffChunkSize = UInt32(36) &+ dataSizeBytes

        header.append(contentsOf: "RIFF".utf8)
        appendLE32(riffChunkSize)
        header.append(contentsOf: "WAVE".utf8)
        header.append(contentsOf: "fmt ".utf8)
        appendLE32(16) // PCM subchunk size
        appendLE16(1)  // Linear PCM format
        appendLE16(safeChannels)
        appendLE32(sampleRateHz)
        appendLE32(byteRate)
        appendLE16(blockAlign)
        appendLE16(safeBits)
        header.append(contentsOf: "data".utf8)
        appendLE32(dataSizeBytes)
        return header
    }

    public init(url: URL, sampleRateHz: UInt32, channels: UInt16 = 1, bitsPerSample: UInt16 = 16) throws {
        self.fileURL = url
        self.sampleRateHz = max(1, sampleRateHz)
        self.channels = max(1, min(8, channels))
        self.bitsPerSample = bitsPerSample == 8 ? 8 : 16

        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO), userInfo: [NSLocalizedDescriptionKey: "Failed to create WAV file at \(url.path)"])
        }
        let handle = try FileHandle(forUpdating: url)
        do {
            let initialHeader = Self.buildWavHeader(
                sampleRateHz: self.sampleRateHz,
                channels: self.channels,
                bitsPerSample: self.bitsPerSample,
                dataSizeBytes: 0
            )
            try handle.write(contentsOf: initialHeader)
        } catch {
            try? handle.close()
            throw error
        }
        self.fileHandle = handle
    }

    public func append(pcmData: Data) throws {
        try lock.withLock {
            guard !isFinalized, let handle = fileHandle else { return }
            let maxWavPayloadBytes = UInt64(UInt32.max - 36)
            guard UInt64(pcmData.count) <= maxWavPayloadBytes - dataBytesWritten else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(EFBIG), userInfo: [NSLocalizedDescriptionKey: "WAV 4 GiB RIFF limit exceeded"])
            }
            if !pcmData.isEmpty {
                try handle.write(contentsOf: pcmData)
                dataBytesWritten += UInt64(pcmData.count)
            }
        }
    }

    @discardableResult
    public func finalize() -> UInt64 {
        lock.withLock {
            guard !isFinalized else { return dataBytesWritten }
            isFinalized = true
            defer {
                try? fileHandle?.close()
                fileHandle = nil
            }
            if let handle = fileHandle {
                let boundedDataSize = UInt32(min(dataBytesWritten, UInt64(UInt32.max - 36)))
                let patched = Self.buildWavHeader(
                    sampleRateHz: sampleRateHz,
                    channels: channels,
                    bitsPerSample: bitsPerSample,
                    dataSizeBytes: boundedDataSize
                )
                do {
                    try handle.seek(toOffset: 0)
                    try handle.write(contentsOf: patched)
                    try handle.synchronize()
                } catch {
                    lastFinalizeError = error.localizedDescription
                }
            }
            return dataBytesWritten
        }
    }

    deinit {
        _ = finalize()
    }
}

/// Real-time Mac PCM speaker player built on AVAudioEngine with Float32 mixer conversion
/// and automatic headless fallback if no audio output hardware is present.
public final class MicLivePlayer: @unchecked Sendable {
    private let lock = NSLock()
    private let sampleRateHz: UInt32
    private let channels: UInt32
    private let prebufferTarget: Int
    private var bufferedCount = 0
    private var inFlightBuffers = 0
    private let maxQueuedBuffers = 25
    private var started = false
    private var stopped = false
    public private(set) var startupErrorMessage: String? = nil

    #if canImport(AVFoundation)
    private var engine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private var renderFormat: AVAudioFormat?
    private var configObserver: NSObjectProtocol?
    #endif

    public init(sampleRateHz: UInt32, channels: UInt32 = 1, prebufferChunks: Int = 2) {
        self.sampleRateHz = max(8000, min(96000, sampleRateHz))
        self.channels = max(1, min(2, channels))
        self.prebufferTarget = max(1, prebufferChunks)

        #if canImport(AVFoundation)
        let format = AVAudioFormat(
            commonFormat: .pcmFormatFloat32,
            sampleRate: Double(self.sampleRateHz),
            channels: AVAudioChannelCount(self.channels),
            interleaved: false
        )
        if let fmt = format {
            let avEngine = AVAudioEngine()
            let node = AVAudioPlayerNode()
            avEngine.attach(node)
            avEngine.connect(node, to: avEngine.mainMixerNode, format: fmt)
            do {
                try avEngine.start()
                self.engine = avEngine
                self.playerNode = node
                self.renderFormat = fmt
                self.configObserver = NotificationCenter.default.addObserver(
                    forName: .AVAudioEngineConfigurationChange,
                    object: avEngine,
                    queue: nil
                ) { [weak self] _ in
                    self?.handleAudioConfigChange()
                }
            } catch {
                // Graceful headless fallback (e.g. CI or no speaker attached)
                self.startupErrorMessage = error.localizedDescription
            }
        }
        #endif
    }

    #if canImport(AVFoundation)
    private func handleAudioConfigChange() {
        lock.withLock {
            guard !stopped, let avEngine = engine else { return }
            if !avEngine.isRunning {
                try? avEngine.start()
            }
        }
    }
    #endif

    public var isAvailable: Bool {
        #if canImport(AVFoundation)
        return lock.withLock { engine != nil && playerNode != nil && renderFormat != nil && !stopped }
        #else
        return false
        #endif
    }

    /// Converts signed 16-bit LE PCM bytes to normalized Float32 [-1.0, 1.0] samples.
    public static func convertInt16PcmToFloat32(_ pcmData: Data) -> [Float] {
        let sampleCount = pcmData.count / 2
        if sampleCount == 0 { return [] }
        var floats = [Float](repeating: 0, count: sampleCount)
        pcmData.withUnsafeBytes { rawBuf in
            let bytes = rawBuf.bindMemory(to: UInt8.self)
            for i in 0..<sampleCount {
                let lo = UInt16(bytes[i * 2])
                let hi = UInt16(bytes[i * 2 + 1])
                let combined = Int16(bitPattern: lo | (hi << 8))
                floats[i] = Float(combined) / 32768.0
            }
        }
        return floats
    }

    public func enqueue(pcmData: Data) {
        #if canImport(AVFoundation)
        lock.withLock {
            guard !stopped, let avEngine = engine, let node = playerNode, let fmt = renderFormat else { return }
            guard inFlightBuffers < maxQueuedBuffers else { return }
            let floats = Self.convertInt16PcmToFloat32(pcmData)
            let frameCount = AVAudioFrameCount(floats.count / Int(channels))
            guard frameCount > 0,
                  let buffer = AVAudioPCMBuffer(pcmFormat: fmt, frameCapacity: frameCount) else { return }
            buffer.frameLength = frameCount
            if let channelData = buffer.floatChannelData {
                let chCount = Int(channels)
                for ch in 0..<chCount {
                    let dst = channelData[ch]
                    for frame in 0..<Int(frameCount) {
                        dst[frame] = floats[frame * chCount + ch]
                    }
                }
            }
            inFlightBuffers += 1
            node.scheduleBuffer(buffer, completionCallbackType: .dataPlayedBack) { [weak self] _ in
                self?.lock.withLock {
                    if let s = self, s.inFlightBuffers > 0 {
                        s.inFlightBuffers -= 1
                    }
                }
            }
            bufferedCount += 1
            if !avEngine.isRunning {
                try? avEngine.start()
            }
            if avEngine.isRunning && (!started && bufferedCount >= prebufferTarget || (started && !node.isPlaying)) {
                node.play()
                started = true
            }
        }
        #endif
    }

    public func drainAndStop(maxWaitMs: Int = 500) {
        #if canImport(AVFoundation)
        let deadline = Date().addingTimeInterval(Double(max(0, maxWaitMs)) / 1000.0)
        while Date() < deadline {
            let remaining = lock.withLock { inFlightBuffers }
            if remaining == 0 { break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        #endif
        stop()
    }

    public func stop() {
        #if canImport(AVFoundation)
        let observer: NSObjectProtocol? = lock.withLock {
            guard !stopped else { return nil }
            stopped = true
            playerNode?.stop()
            engine?.stop()
            playerNode = nil
            engine = nil
            let obs = configObserver
            configObserver = nil
            return obs
        }
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
        #endif
    }

    deinit {
        stop()
    }
}
