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
    private var activeSessionToken: String?
    private var autoReconnectEnabled: Bool = false
    private var reconnectAttempt: Int = 0
    private var reconnectTask: Task<Void, Never>?
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

    public var sessionToken: String? {
        lock.lock()
        defer { lock.unlock() }
        return activeSessionToken
    }

    public enum ControlEvent: Equatable, Sendable {
        case peerOnline(peerDeviceID: String)
        case peerOffline(peerDeviceID: String)
        case relayError(message: String)
    }

    public static func parseControlEvent(from data: Data) -> ControlEvent? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        if let type = json["type"] as? String, type == "PEER_STATUS",
           let peerID = json["peer_device_id"] as? String,
           let isOnline = json["is_online"] as? Bool {
            return isOnline ? .peerOnline(peerDeviceID: peerID) : .peerOffline(peerDeviceID: peerID)
        }
        if let errMsg = json["error"] as? String, json["type"] == nil {
            return .relayError(message: errMsg)
        }
        return nil
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
            setSessionConnected(task: task, token: sessionToken)

            task.resume()
            transition(to: .connected(sessionToken: sessionToken))

            listenForMessages(task)
        } catch {
            transition(to: .error(message: error.localizedDescription))
            scheduleAutoReconnectIfEnabled()
        }
    }

    public func connectWithAutoReconnect() async {
        enableAutoReconnect()
        await connect()
    }

    private func setSessionConnected(task: URLSessionWebSocketTask, token: String) {
        lock.withLock {
            self.webSocketTask = task
            self.activeSessionToken = token
            self.reconnectAttempt = 0
        }
    }

    private func enableAutoReconnect() {
        lock.withLock {
            autoReconnectEnabled = true
            reconnectAttempt = 0
        }
    }

    private func isAutoReconnectEnabled() -> Bool {
        lock.withLock { autoReconnectEnabled }
    }

    private func scheduleAutoReconnectIfEnabled() {
        lock.lock()
        let enabled = autoReconnectEnabled
        if !enabled {
            lock.unlock()
            return
        }
        reconnectAttempt += 1
        let attempt = reconnectAttempt
        reconnectTask?.cancel()
        let maxDelay = min(30.0, pow(2.0, Double(min(attempt - 1, 5))))
        let jitterDelay = (maxDelay / 2.0) + Double.random(in: 0...(maxDelay / 2.0))
        lock.unlock()

        transition(to: .reconnecting(attempt: attempt, delaySeconds: jitterDelay))
        let task = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(jitterDelay * 1_000_000_000))
            guard !Task.isCancelled, let self = self else { return }
            if self.isAutoReconnectEnabled() {
                await self.connect()
            }
        }
        lock.lock()
        reconnectTask = task
        lock.unlock()
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

                // Check if this is a JSON presence or relay error control event
                if let event = Self.parseControlEvent(from: data) {
                    switch event {
                    case .peerOnline(let peerID):
                        self.transition(to: .peerOnline(peerDeviceID: peerID))
                        self.listenForMessages(task)
                        return
                    case .peerOffline(let peerID):
                        self.transition(to: .peerOffline(peerDeviceID: peerID))
                        self.listenForMessages(task)
                        return
                    case .relayError(let errMsg):
                        self.transition(to: .error(message: errMsg))
                        self.scheduleAutoReconnectIfEnabled()
                        return
                    }
                }

                // Regular application / E2E payload
                self.onMessageReceived?(data)

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
                self.scheduleAutoReconnectIfEnabled()
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
        autoReconnectEnabled = false
        reconnectTask?.cancel()
        reconnectTask = nil
        let task = webSocketTask
        webSocketTask = nil
        activeSessionToken = nil
        lock.unlock()

        task?.cancel(with: .normalClosure, reason: nil)
        transition(to: .disconnected)
    }
}

/// SEC-1: TLS SPKI Pinning Delegate
public final class PinnedURLSessionDelegate: NSObject, URLSessionDelegate, Sendable {
    public let pinnedSHA256: String?

    public init(pinnedSHA256: String? = nil) {
        self.pinnedSHA256 = pinnedSHA256
    }

    public static func makeSession(pinnedSHA256: String? = nil) -> URLSession {
        guard let pin = pinnedSHA256, !pin.isEmpty else {
            return .shared
        }
        let delegate = PinnedURLSessionDelegate(pinnedSHA256: pin)
        return URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
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

        var trustError: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &trustError) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
            for cert in chain {
                if let spkiData = Self.subjectPublicKeyInfo(for: cert) {
                    let hash = SHA256.hash(data: spkiData)
                    let hashHex = hash.map { String(format: "%02x", $0) }.joined()
                    let hashB64 = Data(hash).base64EncodedString()
                    if hashHex.caseInsensitiveCompare(expectedPin) == .orderedSame || hashB64 == expectedPin {
                        completionHandler(.useCredential, URLCredential(trust: serverTrust))
                        return
                    }
                }
            }
        }

        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private static func subjectPublicKeyInfo(for cert: SecCertificate) -> Data? {
        guard let secKey = SecCertificateCopyKey(cert),
              let attrs = SecKeyCopyAttributes(secKey) as? [String: Any],
              let rawPub = SecKeyCopyExternalRepresentation(secKey, nil) as Data? else {
            return nil
        }

        let keyType = attrs[kSecAttrKeyType as String] as? String
        let keySize = attrs[kSecAttrKeySizeInBits as String] as? Int ?? 0

        let header: [UInt8]
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && keySize == 256 {
            header = [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00
            ]
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && keySize == 384 {
            header = [
                0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
                0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
            ]
        } else if keyType == (kSecAttrKeyTypeRSA as String) {
            return buildRSASpki(rawPub)
        } else {
            return rawPub
        }

        var spki = Data(header)
        spki.append(rawPub)
        return spki
    }

    private static func buildRSASpki(_ pkcs1: Data) -> Data {
        let oidPrefix: [UInt8] = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        ]
        var bitString = Data([0x03])
        bitString.append(derLength(pkcs1.count + 1))
        bitString.append(0x00)
        bitString.append(pkcs1)

        var inner = Data(oidPrefix)
        inner.append(bitString)

        var spki = Data([0x30])
        spki.append(derLength(inner.count))
        spki.append(inner)
        return spki
    }

    private static func derLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xff), at: 0)
            len >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)] + bytes)
    }
}
