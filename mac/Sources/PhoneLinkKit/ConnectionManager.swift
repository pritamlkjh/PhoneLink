import Foundation
import Security
import CryptoKit

/// MAC-3 / SEC-1: Mac Connection Manager with Certificate Pinning Support
/// Owns the connect/disconnect/reconnect lifecycle, WebSocket transport, certificate pinning, and status reporting.
public final class ConnectionManager: @unchecked Sendable {
    public enum State: Equatable, Sendable {
        case disconnected
        case connecting
        case authenticating
        case connected(sessionToken: String)
        case peerOnline(peerDeviceID: String)
        case peerOffline(peerDeviceID: String)
        case reconnecting(attempt: Int, delaySeconds: Double)
        case error(message: String)

        public var isConnected: BooleanLiteralType {
            switch self {
            case .connected, .peerOnline, .peerOffline: return true
            default: return false
            }
        }
    }

    public typealias StateChangeHandler = @Sendable (State) -> Void
    public typealias MessageHandler = @Sendable (Data) -> Void

    private let vpsBaseURL: URL
    private let identity: DeviceIdentityManager
    private let authClient: AuthClient
    private let urlSession: URLSession

    private var webSocketTask: URLSessionWebSocketTask?
    private var currentState: State = .disconnected
    private let lock = NSLock()

    public var onStateChange: StateChangeHandler?
    public var onMessageReceived: MessageHandler?

    public init(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager = .shared,
        authClient: AuthClient = AuthClient(),
        urlSession: URLSession = .shared
    ) {
        self.vpsBaseURL = vpsBaseURL
        self.identity = identity
        self.authClient = authClient
        self.urlSession = urlSession
    }

    public var state: State {
        lock.lock()
        defer { lock.unlock() }
        return currentState
    }

    private func transition(to newState: State) {
        lock.lock()
        currentState = newState
        let handler = onStateChange
        lock.unlock()

        handler?(newState)
    }

    /// Establishes authentication and opens the WebSocket connection to the VPS.
    public func connect() async {
        transition(to: .connecting)

        do {
            // Step 1: Register device if needed
            try await authClient.registerDevice(vpsBaseURL: vpsBaseURL, identity: identity)

            // Step 2: Authenticate and acquire session token
            transition(to: .authenticating)
            let sessionToken = try await authClient.authenticate(vpsBaseURL: vpsBaseURL, identity: identity)

            // Step 3: Upgrade to WebSocket
            var wsURLComponents = URLComponents(url: vpsBaseURL, resolvingAgainstBaseURL: true)!
            wsURLComponents.scheme = (vpsBaseURL.scheme == "https") ? "wss" : "ws"
            wsURLComponents.path = "/ws/v1/connect"
            wsURLComponents.queryItems = [URLQueryItem(name: "token", value: sessionToken)]

            guard let wsURL = wsURLComponents.url else {
                transition(to: .error(message: "Failed to construct WebSocket URL"))
                return
            }

            let task = urlSession.webSocketTask(with: wsURL)
            setWebSocketTask(task)

            task.resume()
            transition(to: .connected(sessionToken: sessionToken))

            listenForMessages(task)
        } catch {
            transition(to: .error(message: error.localizedDescription))
        }
    }

    /// Connects and waits until the initial peer presence is resolved (or timeout).
    /// Resolves immediately when .peerOnline, .peerOffline, or .error is reached.
    public func connectAndWaitForPresence(timeoutSeconds: Double = 3.0) async -> State {
        await connect()

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            let current = self.state
            switch current {
            case .peerOnline, .peerOffline, .error:
                return current
            default:
                try? await Task.sleep(nanoseconds: 20_000_000) // 20ms poll
            }
        }
        return self.state
    }

    /// Listens continuously for incoming WebSocket frames from the VPS relay.
    private func listenForMessages(_ task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            guard let self = self else { return }

            switch result {
            case .success(let message):
                let data: Data
                switch message {
                case .data(let d):
                    data = d
                case .string(let s):
                    data = Data(s.utf8)
                @unknown default:
                    data = Data()
                }

                // Check if this is a JSON presence event
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let type = json["type"] as? String, type == "PEER_STATUS",
                   let peerID = json["peer_device_id"] as? String,
                   let isOnline = json["is_online"] as? Bool {
                    if isOnline {
                        self.transition(to: .peerOnline(peerDeviceID: peerID))
                    } else {
                        self.transition(to: .peerOffline(peerDeviceID: peerID))
                    }
                } else {
                    // Regular application / E2E payload
                    self.onMessageReceived?(data)
                }

                // Continue listening
                self.listenForMessages(task)

            case .failure(let error):
                self.lock.lock()
                let current = self.currentState
                self.lock.unlock()

                if case .disconnected = current {
                    // Normal disconnect
                    return
                }
                self.transition(to: .error(message: error.localizedDescription))
            }
        }
    }

    private func setWebSocketTask(_ task: URLSessionWebSocketTask?) {
        lock.lock()
        self.webSocketTask = task
        lock.unlock()
    }

    private func getWebSocketTask() -> URLSessionWebSocketTask? {
        lock.lock()
        defer { lock.unlock() }
        return webSocketTask
    }

    /// Sends raw bytes over the WebSocket relay.
    public func send(data: Data) async throws {
        guard let task = getWebSocketTask() else {
            throw AuthClientError.invalidResponse("WebSocket is not connected")
        }
        try await task.send(.data(data))
    }

    /// Disconnects the session.
    public func disconnect() {
        lock.lock()
        let task = webSocketTask
        webSocketTask = nil
        lock.unlock()

        task?.cancel(with: .normalClosure, reason: nil)
        transition(to: .disconnected)
    }
}

/// SEC-1: TLS Certificate Pinning Delegate
public final class PinnedURLSessionDelegate: NSObject, URLSessionDelegate, Sendable {
    public let pinnedSHA256: String?

    public init(pinnedSHA256: String? = nil) {
        self.pinnedSHA256 = pinnedSHA256
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let expectedPin = pinnedSHA256, !expectedPin.isEmpty else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let count = SecTrustGetCertificateCount(serverTrust)
        for i in 0..<count {
            if let cert = SecTrustGetCertificateAtIndex(serverTrust, i) {
                let certData = SecCertificateCopyData(cert) as Data
                let hash = SHA256.hash(data: certData)
                let hashHex = hash.map { String(format: "%02x", $0) }.joined()
                let hashB64 = Data(hash).base64EncodedString()
                if hashHex.caseInsensitiveCompare(expectedPin) == .orderedSame || hashB64 == expectedPin {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
        }

        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
