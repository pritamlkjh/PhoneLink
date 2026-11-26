import Foundation
import CryptoKit

/// Shared authenticated E2E WebSocket transport session for Mac clients (`ActionClient`, `FileClient`, `CameraClient`).
/// Handles:
/// - Peer public key lookup via VPS `/api/v1/devices/status`
/// - Signed `E2E_INIT` & verified `E2E_ACK` handshake
/// - Monotonic AES-256-GCM AAD (`PhoneLink-E2E-v1|M2A|seq` / `A2M`)
/// - `ReplayProtectionFilter` on every decrypted application payload
/// - Immediate failure propagation on relay errors, disconnects, or `.peerOffline`
final class E2ETransportSession: @unchecked Sendable {
    private let lock = NSLock()
    private let e2e = E2EEncryptionManager()
    private let replayFilter = ReplayProtectionFilter()
    private let identity: DeviceIdentityManager
    private let peerIdentityKey: Data?
    private let peerKeyAlgorithm: String?
    private let manager: ConnectionManager

    private var keys: E2EEncryptionManager.SessionKeys?
    private var outgoingSeq: Int64 = 0
    private var lastReceivedSeq: Int64 = -1
    private var terminated = false
    private var activeTimeoutTask: Task<Void, Never>?

    private static let maxHandshakeSkewMs: Int64 = 60_000

    private init(
        manager: ConnectionManager,
        identity: DeviceIdentityManager,
        peerIdentityKey: Data?,
        peerKeyAlgorithm: String?
    ) {
        self.manager = manager
        self.identity = identity
        self.peerIdentityKey = peerIdentityKey
        self.peerKeyAlgorithm = peerKeyAlgorithm
    }

    static func connectAndAuthenticate(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        presenceTimeoutSeconds: Double = 3.0
    ) async throws -> E2ETransportSession {
        let manager = ConnectionManager(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            authClient: client,
            urlSession: client.configuredURLSession
        )
        let presence = await manager.connectAndWaitForPresence(timeoutSeconds: presenceTimeoutSeconds)

        guard case .peerOnline = presence else {
            let reason: String
            if case .error(let msg) = presence {
                reason = msg
            } else {
                reason = "Paired Android device is OFFLINE"
            }
            manager.disconnect()
            throw AuthClientError.invalidResponse(reason)
        }

        var peerPubKey: Data? = nil
        var peerAlg: String? = nil
        if let token = manager.sessionToken,
           let status = try? await client.getDeviceStatus(vpsBaseURL: vpsBaseURL, sessionToken: token),
           let pubB64 = status.peerPublicKey, !pubB64.isEmpty {
            peerPubKey = Data(base64Encoded: pubB64)
            peerAlg = status.peerKeyAlgorithm
        }

        return E2ETransportSession(
            manager: manager,
            identity: identity,
            peerIdentityKey: peerPubKey,
            peerKeyAlgorithm: peerAlg
        )
    }

    func markTerminatedOnce() -> Bool {
        let (didTerminate, taskToCancel): (Bool, Task<Void, Never>?) = lock.withLock {
            if terminated { return (false, nil) }
            terminated = true
            let task = activeTimeoutTask
            activeTimeoutTask = nil
            return (true, task)
        }
        taskToCancel?.cancel()
        return didTerminate
    }

    private func setTimeoutTask(_ task: Task<Void, Never>) {
        let shouldCancel: Bool = lock.withLock {
            if terminated { return true }
            activeTimeoutTask = task
            return false
        }
        if shouldCancel {
            task.cancel()
        }
    }

    func isTerminated() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return terminated
    }

    func disconnect() {
        manager.disconnect()
    }

    private func reserveOutgoingKeyAndSeq() throws -> (SymmetricKey, Int64) {
        try lock.withLock {
            guard let currentKeys = keys else {
                throw AuthClientError.invalidResponse("E2E session keys not established")
            }
            outgoingSeq += 1
            return (currentKeys.keyMacToAndroid, outgoingSeq)
        }
    }

    func sendEncrypted(plaintext: Data) async throws {
        let (sendingKey, seq) = try reserveOutgoingKeyAndSeq()

        let aad = E2EEncryptionManager.buildPayloadAad(direction: "M2A", seq: seq)
        let encrypted = try E2EEncryptionManager.encryptAESGCM(
            key: sendingKey,
            plaintext: plaintext,
            aad: aad
        )

        let payloadJson: [String: Any] = [
            "type": "E2E_PAYLOAD",
            "seq": seq,
            "ciphertext": encrypted.base64EncodedString()
        ]
        let outData = try JSONSerialization.data(withJSONObject: payloadJson)
        try await manager.send(data: outData)
    }

    func runSession<T: Sendable>(
        timeoutSeconds: Double?,
        timeoutMessage: String = "Request timed out waiting for Android response",
        onReady: @escaping @Sendable (E2ETransportSession) async throws -> Void,
        onPayload: @escaping @Sendable (Data, E2ETransportSession, @escaping @Sendable (Result<T, Error>) -> Void) throws -> Void,
        onTerminalState: (@Sendable (ConnectionManager.State, @escaping @Sendable (Result<T, Error>) -> Void) -> Void)? = nil
    ) async throws -> T {
        return try await withCheckedThrowingContinuation { continuation in
            let finish: @Sendable (Result<T, Error>) -> Void = { result in
                if self.markTerminatedOnce() {
                    self.manager.disconnect()
                    continuation.resume(with: result)
                }
            }

            self.manager.onStateChange = { newState in
                guard !self.isTerminated() else { return }
                if let custom = onTerminalState {
                    custom(newState, finish)
                }
                switch newState {
                case .error(let msg):
                    finish(.failure(AuthClientError.invalidResponse("Connection lost: \(msg)")))
                case .disconnected:
                    finish(.failure(AuthClientError.invalidResponse("Connection closed by relay")))
                case .peerOffline:
                    finish(.failure(AuthClientError.invalidResponse("Paired Android device went OFFLINE")))
                default:
                    break
                }
            }

            self.manager.onMessageReceived = { data in
                guard !self.isTerminated() else { return }
                guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let type = json["type"] as? String else {
                    return
                }

                if type == "E2E_ACK" {
                    do {
                        try self.handleAck(json: json)
                        Task {
                            do {
                                try await onReady(self)
                            } catch {
                                finish(.failure(error))
                            }
                        }
                    } catch {
                        finish(.failure(error))
                    }
                } else if type == "E2E_PAYLOAD" {
                    do {
                        let decrypted = try self.decryptIncoming(json: json)
                        try onPayload(decrypted, self, finish)
                    } catch {
                        finish(.failure(error))
                    }
                }
            }

            // Send signed E2E_INIT
            Task {
                do {
                    let ephRaw = self.e2e.publicKeyRaw
                    let ts = Int64(Date().timeIntervalSince1970 * 1000)
                    let transcript = E2EEncryptionManager.buildHandshakeTranscript(ephemeralPublicKey: ephRaw, timestampMs: ts)
                    let sig = try self.identity.sign(data: transcript)

                    let initJson: [String: Any] = [
                        "type": "E2E_INIT",
                        "ephemeral_public_key": ephRaw.base64EncodedString(),
                        "timestamp": ts,
                        "signature": sig.base64EncodedString()
                    ]
                    let initData = try JSONSerialization.data(withJSONObject: initJson)
                    try await self.manager.send(data: initData)
                } catch {
                    finish(.failure(error))
                }
            }

            if let timeout = timeoutSeconds, timeout > 0 {
                self.setTimeoutTask(Task {
                    try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    finish(.failure(AuthClientError.invalidResponse(timeoutMessage)))
                })
            }
        }
    }

    private func handleAck(json: [String: Any]) throws {
        guard let peerPubB64 = json["ephemeral_public_key"] as? String,
              let peerPubData = Data(base64Encoded: peerPubB64) else {
            throw AuthClientError.invalidResponse("Malformed E2E_ACK: missing ephemeral public key")
        }

        if let expectedIdentityKey = peerIdentityKey {
            guard let ts = (json["timestamp"] as? NSNumber)?.int64Value,
                  abs(Int64(Date().timeIntervalSince1970 * 1000) - ts) <= Self.maxHandshakeSkewMs else {
                throw AuthClientError.unauthorized("E2E_ACK timestamp outside allowed skew")
            }
            guard let sigB64 = json["signature"] as? String,
                  let sigData = Data(base64Encoded: sigB64) else {
                throw AuthClientError.unauthorized("E2E_ACK missing peer identity signature")
            }
            let transcript = E2EEncryptionManager.buildHandshakeTranscript(ephemeralPublicKey: peerPubData, timestampMs: ts)
            guard E2EEncryptionManager.verifyPeerSignature(
                publicKeyBytes: expectedIdentityKey,
                algorithm: peerKeyAlgorithm,
                message: transcript,
                signature: sigData
            ) else {
                throw AuthClientError.unauthorized("E2E_ACK peer identity signature verification failed")
            }
        }

        let derived = try e2e.deriveSessionKeys(peerPublicKeyData: peerPubData)
        lock.lock()
        self.keys = derived
        self.outgoingSeq = 0
        self.lastReceivedSeq = -1
        lock.unlock()
    }

    private func decryptIncoming(json: [String: Any]) throws -> Data {
        lock.lock()
        guard let currentKeys = keys else {
            lock.unlock()
            throw AuthClientError.invalidResponse("Received E2E_PAYLOAD before key agreement")
        }
        let prevSeq = lastReceivedSeq
        lock.unlock()

        guard let ctB64 = json["ciphertext"] as? String,
              let ct = Data(base64Encoded: ctB64) else {
            throw AuthClientError.invalidResponse("Malformed E2E_PAYLOAD ciphertext")
        }

        let seqNum = (json["seq"] as? NSNumber)?.int64Value
        let aad: Data?
        if let seq = seqNum {
            if seq <= prevSeq {
                throw AuthClientError.unauthorized("Replayed or out-of-order E2E sequence number \(seq)")
            }
            aad = E2EEncryptionManager.buildPayloadAad(direction: "A2M", seq: seq)
        } else {
            if peerIdentityKey != nil {
                throw AuthClientError.unauthorized("Missing sequence number in E2E_PAYLOAD")
            }
            aad = nil
        }

        let plaintext = try E2EEncryptionManager.decryptAESGCM(
            key: currentKeys.keyAndroidToMac,
            payload: ct,
            aad: aad
        )

        if let seq = seqNum {
            lock.lock()
            if seq <= lastReceivedSeq {
                lock.unlock()
                throw AuthClientError.unauthorized("Concurrent replayed E2E sequence number \(seq)")
            }
            lastReceivedSeq = seq
            lock.unlock()
        }

        let validation = replayFilter.validateMessage(data: plaintext)
        if case .rejected(let status, let msg) = validation {
            throw AuthClientError.unauthorized("\(status): \(msg)")
        }

        return plaintext
    }
}
