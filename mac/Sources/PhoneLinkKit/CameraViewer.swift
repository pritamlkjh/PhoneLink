import Foundation
#if canImport(ImageIO) && canImport(CoreGraphics)
import ImageIO
import CoreGraphics
#endif

/// CAM-4: Mac Camera Viewer Client Models, State Machine & Renderers.
///
/// Implements:
/// 1. CameraViewerState state machine with distinct active, stale, stopped, and inactive states.
/// 2. CameraViewerController with thread-safe state management and stale frame watchdog.
/// 3. CameraTerminalRenderer for rendering live ANSI/ASCII preview canvases in terminal environments.
///
/// ACCEPTANCE CRITERIA:
/// - Displays incoming frames when active.
/// - Clearly displays inactive/stopped state otherwise.
/// - Never shows a stale frame without explicitly indicating the stream has stalled or stopped.

public enum CameraViewerState: Equatable, Sendable {
    case inactive(reason: String)
    case connecting
    case active(frameNumber: UInt64, latencyMs: Int64, fps: Double, timestamp: Date)
    case stale(lastFrameNumber: UInt64, timeSinceLastFrameMs: Int64)
    case stopped(reason: String)
    case error(String)

    public var isActive: Bool {
        if case .active = self { return true }
        return false
    }

    public var statusBadge: String {
        switch self {
        case .inactive:
            return "\u{001B}[31m○ INACTIVE\u{001B}[0m"
        case .connecting:
            return "\u{001B}[33m◌ CONNECTING\u{001B}[0m"
        case .active:
            return "\u{001B}[32m● LIVE [ACTIVE]\u{001B}[0m"
        case .stale:
            return "\u{001B}[33m▲ STALE [STREAM INTERRUPTED]\u{001B}[0m"
        case .stopped:
            return "\u{001B}[31m■ STOPPED\u{001B}[0m"
        case .error:
            return "\u{001B}[31m✖ ERROR\u{001B}[0m"
        }
    }

    public var statusDescription: String {
        switch self {
        case .inactive(let reason):
            return "INACTIVE (\(reason))"
        case .connecting:
            return "Connecting to VPS relay & phone camera..."
        case .active(let fn, let lat, let fps, _):
            return String(format: "Frame #%llu | Latency: %lld ms | Rate: %.1f FPS", fn, lat, fps)
        case .stale(let fn, let elapsed):
            return String(format: "Stale frame #%llu received %lld ms ago (stream stalled)", fn, elapsed)
        case .stopped(let reason):
            return "Camera stream stopped (\(reason)) - hardware sensor deactivated"
        case .error(let msg):
            return "Stream error: \(msg)"
        }
    }
}

public final class CameraViewerController: @unchecked Sendable {
    private let lock = NSLock()
    private var currentState: CameraViewerState = .inactive(reason: "not_started")
    private var lastFrameTime: Date?
    private var lastFrame: CameraFrame?
    private var onStateChanged: (@Sendable (CameraViewerState) -> Void)?
    public let staleTimeoutMs: Int64

    public init(staleTimeoutMs: Int64 = 2500, onStateChanged: (@Sendable (CameraViewerState) -> Void)? = nil) {
        self.staleTimeoutMs = staleTimeoutMs
        self.onStateChanged = onStateChanged
    }

    public var state: CameraViewerState {
        lock.lock()
        defer { lock.unlock() }
        return currentState
    }

    public var currentLastFrame: CameraFrame? {
        lock.lock()
        defer { lock.unlock() }
        return lastFrame
    }

    public func setOnStateChanged(_ handler: (@Sendable (CameraViewerState) -> Void)?) {
        lock.lock()
        defer { lock.unlock() }
        onStateChanged = handler
    }

    public func notifyConnecting() {
        transitionTo(.connecting)
    }

    public func notifyFrameReceived(frame: CameraFrame, stats: CameraStreamStats) {
        lock.lock()
        lastFrameTime = Date()
        lastFrame = frame
        let newState = CameraViewerState.active(
            frameNumber: frame.frameNumber,
            latencyMs: stats.lastLatencyMs,
            fps: stats.currentFps,
            timestamp: Date()
        )
        currentState = newState
        let cb = onStateChanged
        lock.unlock()
        cb?(newState)
    }

    public func checkStale() -> Bool {
        lock.lock()
        guard case .active(let fn, _, _, _) = currentState, let last = lastFrameTime else {
            lock.unlock()
            return false
        }
        let elapsedMs = Int64(Date().timeIntervalSince(last) * 1000)
        if elapsedMs > staleTimeoutMs {
            let newState = CameraViewerState.stale(lastFrameNumber: fn, timeSinceLastFrameMs: elapsedMs)
            currentState = newState
            let cb = onStateChanged
            lock.unlock()
            cb?(newState)
            return true
        }
        lock.unlock()
        return false
    }

    public func notifyStopped(reason: String = "user_stopped") {
        transitionTo(.stopped(reason: reason))
    }

    public func notifyInactive(reason: String = "camera_deactivated") {
        transitionTo(.inactive(reason: reason))
    }

    public func notifyError(message: String) {
        transitionTo(.error(message))
    }

    private func transitionTo(_ newState: CameraViewerState) {
        lock.lock()
        currentState = newState
        let cb = onStateChanged
        lock.unlock()
        cb?(newState)
    }
}

public struct CameraTerminalRenderer: Sendable {
    private static let shadedChars: [Character] = [" ", ".", ":", "░", "▒", "▓", "█"]

    /// Generates a structured terminal status banner for live stream viewing.
    public static func renderBanner(
        state: CameraViewerState,
        lens: CameraLens = .back,
        width: UInt32 = 1280,
        height: UInt32 = 720,
        frameBytes: Int = 0
    ) -> String {
        var lines: [String] = []
        lines.append("┌────────────────────────────────────────────────────────────────────────┐")
        let lensPadded = lens.rawValue.padding(toLength: 18, withPad: " ", startingAt: 0)
        lines.append("│ PhoneLink Camera Preview (CAM-4)              Lens: \(lensPadded) │")
        lines.append("│ Status: " + state.statusBadge.padding(toLength: 70, withPad: " ", startingAt: 0) + " │")
        let infoPadded = truncateString(state.statusDescription, maxLength: 62).padding(toLength: 62, withPad: " ", startingAt: 0)
        lines.append("│ Info:   \(infoPadded) │")

        if state.isActive {
            let sizeKB = Double(frameBytes) / 1024.0
            let streamInfo = String(format: "%ux%u JPEG (%.1f KB)", width, height, sizeKB).padding(toLength: 35, withPad: " ", startingAt: 0)
            lines.append("│ Stream: \(streamInfo)     OS Dot: ACTIVE ●   │")
        } else {
            lines.append("│ Hardware: Inactive / Closed                          OS Dot: OFF   ○   │")
        }
        lines.append("└────────────────────────────────────────────────────────────────────────┘")
        return lines.joined(separator: "\n")
    }

    /// Generates an ASCII preview canvas representing the frame.
    public static func renderAsciiCanvas(
        frame: CameraFrame?,
        state: CameraViewerState,
        columns: Int = 40,
        rows: Int = 12
    ) -> String {
        var lines: [String] = []

        if !state.isActive || frame == nil {
            // Distinct Inactive Screen
            lines.append("  +" + String(repeating: "-", count: columns) + "+")
            let middleRow = rows / 2
            for r in 0..<rows {
                if r == middleRow - 1 {
                    let msg = "[ STREAM INACTIVE ]"
                    let text = centerText(msg, width: columns)
                    lines.append("  |" + text + "|")
                } else if r == middleRow {
                    let msg = "Camera sensor is powered off"
                    let text = centerText(msg, width: columns)
                    lines.append("  |" + text + "|")
                } else {
                    lines.append("  |" + String(repeating: " ", count: columns) + "|")
                }
            }
            lines.append("  +" + String(repeating: "-", count: columns) + "+")
            return lines.joined(separator: "\n")
        }

        // Active Frame Canvas
        let jpeg = frame!.jpegData
        lines.append("  +" + String(repeating: "-", count: columns) + "+")

        if let lumaRows = decodeGrayscaleAsciiGrid(jpegData: jpeg, columns: columns, rows: rows) {
            for rowStr in lumaRows {
                lines.append("  |" + rowStr + "|")
            }
        } else {
            // Fallback block representation when raw payload is non-image test fixture data
            var byteIdx = 0
            for r in 0..<rows {
                var rowChars: [Character] = []
                for c in 0..<columns {
                    let seed = byteIdx < jpeg.count ? Int(jpeg[byteIdx]) : (r * columns + c)
                    let charIdx = (seed + r + c) % shadedChars.count
                    rowChars.append(shadedChars[charIdx])
                    byteIdx = (byteIdx + 7) % max(1, jpeg.count)
                }
                lines.append("  |" + String(rowChars) + "|")
            }
        }
        lines.append("  +" + String(repeating: "-", count: columns) + "+")
        return lines.joined(separator: "\n")
    }

    private static func decodeGrayscaleAsciiGrid(jpegData: Data, columns: Int, rows: Int) -> [String]? {
        guard columns > 0, rows > 0 else { return nil }
        #if canImport(ImageIO) && canImport(CoreGraphics)
        guard let source = CGImageSourceCreateWithData(jpegData as CFData, nil),
              let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
            return nil
        }

        var pixels = [UInt8](repeating: 0, count: columns * rows)
        let colorSpace = CGColorSpaceCreateDeviceGray()
        guard let context = CGContext(
                data: &pixels,
                width: columns,
                height: rows,
                bitsPerComponent: 8,
                bytesPerRow: columns,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.none.rawValue
              ) else {
            return nil
        }
        context.interpolationQuality = .medium
        context.draw(cgImage, in: CGRect(x: 0, y: 0, width: columns, height: rows))

        var minLum = 255
        var maxLum = 0
        for px in pixels {
            let v = Int(px)
            if v < minLum { minLum = v }
            if v > maxLum { maxLum = v }
        }
        let spread = maxLum - minLum
        let stretchContrast = (spread >= 16 && maxLum < 220)

        var out: [String] = []
        out.reserveCapacity(rows)
        let denom = max(1, shadedChars.count - 1)
        for r in 0..<rows {
            var chars: [Character] = []
            chars.reserveCapacity(columns)
            for c in 0..<columns {
                let rawLum = Int(pixels[r * columns + c])
                let lum = stretchContrast ? (((rawLum - minLum) * 255) / spread) : rawLum
                let idx = min(denom, (max(0, lum) * shadedChars.count) / 256)
                chars.append(shadedChars[idx])
            }
            out.append(String(chars))
        }
        return out
        #else
        return nil
        #endif
    }

    private static func centerText(_ text: String, width: Int) -> String {
        if text.count >= width {
            return String(text.prefix(width))
        }
        let leftPad = (width - text.count) / 2
        let rightPad = width - text.count - leftPad
        return String(repeating: " ", count: leftPad) + text + String(repeating: " ", count: rightPad)
    }

    private static func truncateString(_ str: String, maxLength: Int) -> String {
        if str.count <= maxLength {
            return str
        }
        let index = str.index(str.startIndex, offsetBy: maxLength - 3)
        return String(str[..<index]) + "..."
    }
}
