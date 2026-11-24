import Foundation

/// Errors that can occur during Mac VPS authentication.
public enum AuthClientError: Error, LocalizedError {
    case invalidURL
    case serverError(statusCode: Int, message: String)
    case invalidResponse(String)
    case unauthorized(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid VPS URL"
        case .serverError(let code, let msg): return "VPS server error (HTTP \(code)): \(msg)"
        case .invalidResponse(let msg): return "Invalid response from VPS: \(msg)"
        case .unauthorized(let msg): return "Authentication failed: \(msg)"
        }
    }
}

/// MAC-2: AuthClient manages device registration, challenge-response handshake, and pairing tokens.
public struct AuthClient: Sendable {
    private let urlSession: URLSession

    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
    }

    /// Registers the Mac device public key with the VPS registry.
    public func registerDevice(vpsBaseURL: URL, identity: DeviceIdentityManager) async throws {
        let registerEndpoint = vpsBaseURL.appendingPathComponent("/api/v1/devices/register")
        var request = URLRequest(url: registerEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "device_id": identity.deviceID,
            "device_type": "mac",
            "public_key": identity.publicKeyBase64,
            "key_algorithm": "ED25519"
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthClientError.invalidResponse("Not an HTTP response")
        }

        if httpResponse.statusCode != 201 && httpResponse.statusCode != 409 { // 409 = already registered
            let errMsg = String(data: data, encoding: .utf8) ?? "Unknown registration error"
            throw AuthClientError.serverError(statusCode: httpResponse.statusCode, message: errMsg)
        }
    }

    /// Performs the full challenge-response authentication against VPS-2, returning a session token.
    public func authenticate(vpsBaseURL: URL, identity: DeviceIdentityManager) async throws -> String {
        // Step 1: Request Challenge
        let challengeEndpoint = vpsBaseURL.appendingPathComponent("/api/v1/auth/challenge")
        var chReq = URLRequest(url: challengeEndpoint)
        chReq.httpMethod = "POST"
        chReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        chReq.httpBody = try JSONSerialization.data(withJSONObject: ["device_id": identity.deviceID])

        let (chData, chResp) = try await urlSession.data(for: chReq)
        guard let chHTTP = chResp as? HTTPURLResponse else {
            throw AuthClientError.invalidResponse("Not an HTTP response")
        }
        guard chHTTP.statusCode == 200 else {
            let msg = String(data: chData, encoding: .utf8) ?? ""
            throw AuthClientError.unauthorized("Challenge request rejected: \(msg)")
        }

        guard let chJSON = try JSONSerialization.jsonObject(with: chData) as? [String: Any],
              let serverNonceB64 = chJSON["server_nonce"] as? String,
              let serverNonce = Data(base64Encoded: serverNonceB64),
              let timestamp = chJSON["timestamp"] as? Int64 else {
            throw AuthClientError.invalidResponse("Malformed challenge response from VPS")
        }

        // Step 2: Generate random 32-byte client nonce and sign
        var clientNonce = Data(count: 32)
        _ = clientNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let signature = try identity.signChallenge(serverNonce: serverNonce, clientNonce: clientNonce, timestamp: timestamp)

        // Step 3: Verify with VPS
        let verifyEndpoint = vpsBaseURL.appendingPathComponent("/api/v1/auth/verify")
        var verReq = URLRequest(url: verifyEndpoint)
        verReq.httpMethod = "POST"
        verReq.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let verBody: [String: Any] = [
            "device_id": identity.deviceID,
            "server_nonce": serverNonceB64,
            "client_nonce": clientNonce.base64EncodedString(),
            "timestamp": timestamp,
            "signature": signature.base64EncodedString()
        ]
        verReq.httpBody = try JSONSerialization.data(withJSONObject: verBody)

        let (verData, verResp) = try await urlSession.data(for: verReq)
        guard let verHTTP = verResp as? HTTPURLResponse else {
            throw AuthClientError.invalidResponse("Not an HTTP response")
        }
        guard verHTTP.statusCode == 200 else {
            let msg = String(data: verData, encoding: .utf8) ?? ""
            throw AuthClientError.unauthorized("Authentication failed: \(msg)")
        }

        guard let verJSON = try JSONSerialization.jsonObject(with: verData) as? [String: Any],
              let sessionToken = verJSON["session_token"] as? String else {
            throw AuthClientError.invalidResponse("Missing session token in auth response")
        }

        return sessionToken
    }

    /// Generates a one-time pairing token for out-of-band QR ceremony.
    public func createPairingToken(vpsBaseURL: URL, deviceID: String) async throws -> String {
        let endpoint = vpsBaseURL.appendingPathComponent("/api/v1/pairing/create")
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["device_id": deviceID])

        let (data, response) = try await urlSession.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let msg = String(data: data, encoding: .utf8) ?? ""
            throw AuthClientError.serverError(statusCode: (response as? HTTPURLResponse)?.statusCode ?? 500, message: msg)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["pairing_token"] as? String else {
            throw AuthClientError.invalidResponse("Missing pairing_token in response")
        }

        return token
    }
}
