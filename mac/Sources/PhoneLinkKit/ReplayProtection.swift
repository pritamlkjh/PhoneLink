import Foundation

/// SEC-1: Mac Replay Protection Filter.
/// Validates timestamp freshness and message_id uniqueness across incoming ApplicationMessages.
public final class ReplayProtectionFilter: @unchecked Sendable {
    public static let defaultMaxClockSkewMs: Int64 = 60_000 // 60s
    public static let defaultMaxCacheSize: Int = 5_000

    public static let statusOk = "STATUS_OK"
    public static let statusMessageExpired = "STATUS_MESSAGE_EXPIRED"
    public static let statusReplayDetected = "STATUS_REPLAY_DETECTED"
    public static let statusMalformedMessage = "STATUS_MALFORMED_MESSAGE"

    public enum ValidationResult: Equatable, Sendable {
        case valid
        case rejected(status: String, message: String)
    }

    private let lock = NSLock()
    private let maxClockSkewMs: Int64
    private let maxCacheSize: Int
    private var seenMessageIds: [String: Int64] = [:]
    private var insertionOrder: [String] = []
    private var insertionHeadIndex: Int = 0
    private var totalValidated: UInt64 = 0
    private var totalReplayed: UInt64 = 0
    private var totalExpired: UInt64 = 0
    private let timeProvider: @Sendable () -> Int64

    public init(
        maxClockSkewMs: Int64 = defaultMaxClockSkewMs,
        maxCacheSize: Int = defaultMaxCacheSize,
        timeProvider: (@Sendable () -> Int64)? = nil
    ) {
        self.maxClockSkewMs = max(0, maxClockSkewMs)
        self.maxCacheSize = max(1, maxCacheSize)
        self.timeProvider = timeProvider ?? { Int64(Date().timeIntervalSince1970 * 1000) }
    }

    public func validateMessage(data: Data) -> ValidationResult {
        lock.lock()
        defer { lock.unlock() }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .rejected(status: Self.statusMalformedMessage, message: "Payload is not valid JSON")
        }

        guard let messageId = json["message_id"] as? String, !messageId.isEmpty else {
            return .rejected(status: Self.statusMalformedMessage, message: "Missing required 'message_id'")
        }

        guard let timestampNum = json["timestamp"] as? NSNumber else {
            return .rejected(status: Self.statusMalformedMessage, message: "Missing required 'timestamp'")
        }
        let timestamp = timestampNum.int64Value
        let now = timeProvider()
        // Overflow-safe magnitude comparison across full signed 64-bit integer range (avoids SIGILL on Int64.min)
        let skewMagnitude: UInt64 = now >= timestamp
            ? UInt64(bitPattern: now) &- UInt64(bitPattern: timestamp)
            : UInt64(bitPattern: timestamp) &- UInt64(bitPattern: now)
        let maxSkewUInt = UInt64(maxClockSkewMs)

        // 1. Clock skew / freshness check
        if skewMagnitude > maxSkewUInt {
            totalExpired += 1
            return .rejected(
                status: Self.statusMessageExpired,
                message: "Message timestamp (\(timestamp)) exceeds max clock skew (\(skewMagnitude)ms > \(maxClockSkewMs)ms)"
            )
        }

        // 2. Replay detection check
        if seenMessageIds[messageId] != nil {
            totalReplayed += 1
            return .rejected(
                status: Self.statusReplayDetected,
                message: "Duplicate message_id '\(messageId)' rejected by replay protection"
            )
        }

        // Prune expired / oldest FIFO entries in O(1) amortized to keep memory bounded
        while seenMessageIds.count >= maxCacheSize && insertionHeadIndex < insertionOrder.count {
            let oldestId = insertionOrder[insertionHeadIndex]
            insertionHeadIndex += 1
            seenMessageIds.removeValue(forKey: oldestId)
        }
        if insertionHeadIndex > 1024 && insertionHeadIndex * 2 >= insertionOrder.count {
            insertionOrder.removeFirst(insertionHeadIndex)
            insertionHeadIndex = 0
        }

        seenMessageIds[messageId] = timestamp
        insertionOrder.append(messageId)
        totalValidated += 1
        return .valid
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        seenMessageIds.removeAll()
        insertionOrder.removeAll()
        insertionHeadIndex = 0
        totalValidated = 0
        totalReplayed = 0
        totalExpired = 0
    }
}
