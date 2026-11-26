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

        let blockAlign = channels * (bitsPerSample / 8)
        let byteRate = sampleRateHz * UInt32(blockAlign)
        let riffChunkSize = UInt32(36) &+ dataSizeBytes

        header.append(contentsOf: "RIFF".utf8)
        appendLE32(riffChunkSize)
        header.append(contentsOf: "WAVE".utf8)
        header.append(contentsOf: "fmt ".utf8)
        appendLE32(16) // PCM subchunk size
        appendLE16(1)  // Linear PCM format
        appendLE16(channels)
        appendLE32(sampleRateHz)
        appendLE32(byteRate)
        appendLE16(blockAlign)
        appendLE16(bitsPerSample)
        header.append(contentsOf: "data".utf8)
        appendLE32(dataSizeBytes)
        return header
    }

    public init(url: URL, sampleRateHz: UInt32, channels: UInt16 = 1, bitsPerSample: UInt16 = 16) throws {
        self.fileURL = url
        self.sampleRateHz = sampleRateHz
        self.channels = channels
        self.bitsPerSample = bitsPerSample

        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forUpdating: url)
        let initialHeader = Self.buildWavHeader(
            sampleRateHz: sampleRateHz,
            channels: channels,
            bitsPerSample: bitsPerSample,
            dataSizeBytes: 0
        )
        try handle.write(contentsOf: initialHeader)
        self.fileHandle = handle
    }

    public func append(pcmData: Data) throws {
        try lock.withLock {
            guard !isFinalized, let handle = fileHandle else { return }
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
                } catch {}
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
    private var started = false
    private var stopped = false
    public private(set) var startupErrorMessage: String? = nil

    #if canImport(AVFoundation)
    private var engine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private var renderFormat: AVAudioFormat?
    #endif

    public init(sampleRateHz: UInt32, channels: UInt32 = 1, prebufferChunks: Int = 2) {
        self.sampleRateHz = sampleRateHz
        self.channels = max(1, channels)
        self.prebufferTarget = max(1, prebufferChunks)

        #if canImport(AVFoundation)
        let format = AVAudioFormat(
            commonFormat: .pcmFormatFloat32,
            sampleRate: Double(sampleRateHz),
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
            } catch {
                // Graceful headless fallback (e.g. CI or no speaker attached)
                self.startupErrorMessage = error.localizedDescription
            }
        }
        #endif
    }

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
            guard !stopped, let node = playerNode, let fmt = renderFormat else { return }
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
            node.scheduleBuffer(buffer)
            bufferedCount += 1
            if !started && bufferedCount >= prebufferTarget {
                node.play()
                started = true
            }
        }
        #endif
    }

    public func stop() {
        #if canImport(AVFoundation)
        lock.withLock {
            guard !stopped else { return }
            stopped = true
            playerNode?.stop()
            engine?.stop()
            playerNode = nil
            engine = nil
        }
        #endif
    }

    deinit {
        stop()
    }
}
