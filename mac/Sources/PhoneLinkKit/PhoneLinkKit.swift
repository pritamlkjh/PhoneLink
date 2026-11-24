import Foundation

public struct PhoneLinkInfo {
    public static let version = "1.0.0"
    public static let clientName = "PhoneLink Mac Client"
    
    public static func banner() -> String {
        return "\(clientName) v\(version) (macOS Sequoia+)"
    }
}

public enum ConnectionState: String, Sendable {
    case disconnected
    case connecting
    case authenticated
    case peerConnected
    case error
}
