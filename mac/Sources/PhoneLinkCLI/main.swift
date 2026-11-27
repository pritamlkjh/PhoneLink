import Foundation
import PhoneLinkKit

/// MAC-4: PhoneLink Mac Command-Line Interface.
/// Exit Code Conventions:
///   0 = Success
///   1 = Operational / Network / Authentication error
///   2 = Usage / Argument parsing error

struct Config {
    static let defaultRelayURL = ProcessInfo.processInfo.environment["PHONELINK_RELAY_URL"] ?? "http://127.0.0.1:8443"

    static func resolvePinnedSHA256(args: [String]) -> String? {
        if let cliPin = parseStrictOption("--tls-pin", in: args) {
            if cliPin.isEmpty {
                fputs("ERROR: --tls-pin requires a non-empty SHA-256 fingerprint.\n", stderr)
                exit(2)
            }
            return cliPin
        }
        if let envPin = ProcessInfo.processInfo.environment["PHONELINK_TLS_PIN"], !envPin.isEmpty {
            return envPin
        }
        return nil
    }
}

func printUsage() {
    print("""
    OVERVIEW: PhoneLink — Personal authorized remote-access system for macOS and Android.
    
    USAGE: phonelink <subcommand> [options]
    
    SUBCOMMANDS:
      info          Show local Mac device identity (use '--device' for remote phone info)
      device        Execute scoped remote actions on phone (info, ping)
      pair          Initiate pairing ceremony (generates pairing token & short code)
      revoke        Immediately revoke the paired Android device (or '--self' with '--confirm')
      status        Check relay connectivity and Android phone online/offline state
                    Options: --watch (stream real-time updates), --json, --vps <url>
      ping          Send an end-to-end encrypted round-trip ping to the phone
                    Options: --duration <seconds>, --count <n>, --relay (ping relay only), --json
      wipe          Wipe stored credentials and reset Mac device identity
      files         Browse and transfer files (FILE-2, FILE-3, FILE-4)
      camera        Live camera streaming and capture (CAM-3, CAM-4)
      mic           Live microphone listening and WAV recording (owner opt-in)
      install-phone 1-tap OTA phone installation URL & local Wi-Fi QR server
      version       Show PhoneLink version information
      help          Show help information
    
    OPTIONS:
      --vps <url>       Override VPS relay URL (default: \(Config.defaultRelayURL))
      --tls-pin <hash>  Require SHA-256 SPKI pin on HTTPS/WSS connections (or PHONELINK_TLS_PIN)
      --json            Format output as machine-readable JSON
      -h, --help        Show help information
      -v, --version     Show version
    
    EXAMPLES:
      phonelink info
      phonelink pair --vps http://127.0.0.1:8443
      phonelink status --json
      phonelink ping --count 3
      phonelink revoke --vps http://127.0.0.1:8443
    """)
}

func parseFlag(_ flag: String, in args: [String]) -> Bool {
    return args.contains(flag)
}

func parseStrictOption(_ option: String, in args: [String]) -> String? {
    for (idx, arg) in args.enumerated() {
        if arg == option {
            guard idx + 1 < args.count else {
                fputs("ERROR: Missing value for option '\(option)'.\n", stderr)
                exit(2)
            }
            let val = args[idx + 1]
            if val.hasPrefix("--") {
                fputs("ERROR: Missing value for option '\(option)' (got flag '\(val)').\n", stderr)
                exit(2)
            }
            return val
        }
        let eqPrefix = option + "="
        if arg.hasPrefix(eqPrefix) {
            let val = String(arg.dropFirst(eqPrefix.count))
            if val.isEmpty {
                fputs("ERROR: Empty value for option '\(option)'.\n", stderr)
                exit(2)
            }
            return val
        }
    }
    return nil
}

func parseOption(_ option: String, in args: [String]) -> String? {
    return parseStrictOption(option, in: args)
}

func parsePositionalArgs(in args: [String], valuedOptions: Set<String>) -> [String] {
    var result: [String] = []
    var i = 0
    while i < args.count {
        let arg = args[i]
        if valuedOptions.contains(arg) {
            i += 2
            continue
        }
        if valuedOptions.contains(where: { arg.hasPrefix($0 + "=") }) {
            i += 1
            continue
        }
        if arg.hasPrefix("-") {
            i += 1
            continue
        }
        result.append(arg)
        i += 1
    }
    return result
}

func resolveRelayURL(from args: [String]) -> URL {
    let raw = (parseStrictOption("--vps", in: args) ?? Config.defaultRelayURL).trimmingCharacters(in: .whitespacesAndNewlines)
    guard !raw.isEmpty, var comps = URLComponents(string: raw) else {
        fputs("ERROR: Invalid VPS relay URL: \(raw)\n", stderr)
        exit(2)
    }
    let lowerScheme = comps.scheme?.lowercased() ?? ""
    if lowerScheme == "ws" {
        comps.scheme = "http"
    } else if lowerScheme == "wss" {
        comps.scheme = "https"
    } else {
        comps.scheme = lowerScheme
    }
    guard let scheme = comps.scheme, (scheme == "http" || scheme == "https"),
          let host = comps.host, !host.isEmpty,
          let normalized = comps.url else {
        fputs("ERROR: Invalid VPS relay URL '\(raw)'. Expected http(s)://host[:port].\n", stderr)
        exit(2)
    }
    return normalized
}

func parseFiniteDoubleOption(
    _ option: String,
    in args: [String],
    default defaultValue: Double,
    min minVal: Double,
    max maxVal: Double,
    clampWithNote: Bool = false
) -> Double {
    guard let raw = parseStrictOption(option, in: args) else { return defaultValue }
    guard let val = Double(raw), val.isFinite, val > 0 else {
        fputs("ERROR: Invalid value '\(raw)' for \(option). Expected a finite positive number.\n", stderr)
        exit(2)
    }
    if val < minVal || val > maxVal {
        if clampWithNote {
            let clamped = Swift.min(Swift.max(val, minVal), maxVal)
            fputs("Note: Clamping \(option) \(raw) to supported range \(minVal)...\(maxVal).\n", stderr)
            return clamped
        }
        fputs("ERROR: Value '\(raw)' for \(option) out of range (\(minVal)...\(maxVal)).\n", stderr)
        exit(2)
    }
    return val
}

func parseStrictUInt32Option(
    _ option: String,
    in args: [String],
    default defaultValue: UInt32,
    min minVal: UInt32,
    max maxVal: UInt32,
    clampWithNote: Bool = false
) -> UInt32 {
    guard let raw = parseStrictOption(option, in: args) else { return defaultValue }
    guard let val = UInt32(raw), val > 0 else {
        fputs("ERROR: Invalid value '\(raw)' for \(option). Expected a positive integer.\n", stderr)
        exit(2)
    }
    if val < minVal || val > maxVal {
        if clampWithNote {
            let clamped = Swift.min(Swift.max(val, minVal), maxVal)
            fputs("Note: Clamping \(option) \(raw) to supported range \(minVal)...\(maxVal).\n", stderr)
            return clamped
        }
        fputs("ERROR: Value '\(raw)' for \(option) out of range (\(minVal)...\(maxVal)).\n", stderr)
        exit(2)
    }
    return val
}

func parseStrictUInt64Option(_ option: String, in args: [String], min minVal: UInt64 = 1) -> UInt64? {
    guard let raw = parseStrictOption(option, in: args) else { return nil }
    guard let val = UInt64(raw), val >= minVal else {
        fputs("ERROR: Invalid value '\(raw)' for \(option). Expected an integer >= \(minVal).\n", stderr)
        exit(2)
    }
    return val
}

func parseStrictIntOption(_ option: String, in args: [String], default defaultValue: Int, min minVal: Int, max maxVal: Int) -> Int {
    guard let raw = parseStrictOption(option, in: args) else { return defaultValue }
    guard let val = Int(raw), val >= minVal && val <= maxVal else {
        fputs("ERROR: Invalid value '\(raw)' for \(option). Expected integer \(minVal)...\(maxVal).\n", stderr)
        exit(2)
    }
    return val
}

func printJSON(_ dict: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
          let str = String(data: data, encoding: .utf8) else {
        fputs("ERROR: Failed to serialize JSON output.\n", stderr)
        return
    }
    print(str)
}

func handleInfo(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isDevice = parseFlag("--device", in: args)
    let vpsStr = parseStrictOption("--vps", in: args) ?? Config.defaultRelayURL

    if isDevice {
        let vpsURL = resolveRelayURL(from: args)
        do {
            let resp = try await ActionClient.fetchDeviceInfo(vpsBaseURL: vpsURL, identity: identity, client: client)
            if isJSON {
                let dict: [String: Any] = [
                    "request_id": resp.requestId,
                    "status": resp.status,
                    "model": resp.model,
                    "os_version": resp.osVersion,
                    "battery_percent": resp.batteryPercent,
                    "is_charging": resp.isCharging,
                    "total_storage_bytes": resp.totalStorageBytes,
                    "available_storage_bytes": resp.availableStorageBytes,
                    "app_version": resp.appVersion,
                    "error_message": resp.errorMessage ?? ""
                ]
                printJSON(dict)
            } else if resp.status != "STATUS_OK" {
                let err = resp.errorMessage ?? resp.status
                fputs("ERROR: Remote device info failed (\(resp.status)): \(err)\n", stderr)
            } else {
                print("PhoneLink Remote Device Info")
                print("--------------------------------------------------")
                print("Device Model:      \(resp.model)")
                print("OS Version:        \(resp.osVersion)")
                let chargingStr = resp.isCharging ? " (Charging)" : ""
                print("Battery:           \(resp.batteryPercent)%\(chargingStr)")
                print("Total Storage:     \(FileClient.formatByteSize(resp.totalStorageBytes))")
                print("Available Storage: \(FileClient.formatByteSize(resp.availableStorageBytes))")
                print("App Version:       \(resp.appVersion)")
            }
            exit(resp.status == "STATUS_OK" ? 0 : 1)
        } catch {
            if isJSON {
                printJSON([
                    "status": "ERROR",
                    "error_message": error.localizedDescription
                ])
            } else {
                fputs("ERROR: Failed to fetch remote device info: \(error.localizedDescription)\n", stderr)
            }
            exit(1)
        }
    }

    let devID = identity.deviceID
    let pubKey = identity.publicKeyBase64

    if isJSON {
        let dict: [String: Any] = [
            "client": PhoneLinkInfo.clientName,
            "version": PhoneLinkInfo.version,
            "device_id": devID,
            "public_key": pubKey,
            "key_algorithm": "ED25519",
            "relay_url": vpsStr
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
           let str = String(data: data, encoding: .utf8) {
            print(str)
        }
    } else {
        print("PhoneLink Mac Client v\(PhoneLinkInfo.version)")
        print("--------------------------------------------------")
        print("Device ID:      \(devID)")
        print("Key Algorithm:  Ed25519 (RFC 8032)")
        print("Public Key:     \(pubKey)")
        print("Relay Endpoint: \(vpsStr)")
        print("\nTip: Run 'phonelink info --device' or 'phonelink device info' to query connected Android phone telemetry.")
    }
    exit(0)
}

func handleWipe(args: [String], identity: DeviceIdentityManager) {
    let confirm = parseFlag("--confirm", in: args) || parseFlag("-y", in: args)
    if !confirm {
        print("CAUTION: Wiping device identity will sever pairing with your Android device.")
        print("Run 'phonelink wipe --confirm' to proceed.")
        exit(1)
    }

    identity.wipeIdentity()
    print("SUCCESS: Local Mac identity and credentials wiped.")
    print("New Device ID: \(identity.deviceID)")
    exit(0)
}

func handlePair(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let vpsURL = resolveRelayURL(from: args)

    do {
        // Register device if not yet registered and authenticate for Bearer token
        try await client.registerDevice(vpsBaseURL: vpsURL, identity: identity)
        let sessionToken = try await client.authenticate(vpsBaseURL: vpsURL, identity: identity)

        // Generate one-time pairing token
        let token = try await client.createPairingToken(
            vpsBaseURL: vpsURL,
            deviceID: identity.deviceID,
            sessionToken: sessionToken
        )
        let shortCode = String(token.prefix(8)).uppercased()

        if isJSON {
            let dict: [String: Any] = [
                "status": "OK",
                "device_id": identity.deviceID,
                "pairing_token": token,
                "short_code": shortCode,
                "expires_in_seconds": 300
            ]
            printJSON(dict)
        } else {
            print("==================================================")
            print("        PHONELINK OUT-OF-BAND PAIRING")
            print("==================================================")
            print("Mac Device ID: \(identity.deviceID)")
            print("Pairing Token: \(token)")
            print("Short Code:    [\(shortCode)]")
            print("")
            print("Scan QR code or enter this short code on your Android device.")
            print("Token expires in 300 seconds.")
            print("==================================================")
        }
        exit(0)
    } catch {
        fputs("ERROR: Pairing ceremony failed: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}

func handleRevoke(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let revokeSelf = parseFlag("--self", in: args)
    let confirm = parseFlag("--confirm", in: args) || parseFlag("-y", in: args)
    let explicitDevice = parseStrictOption("--device", in: args)
    let vpsURL = resolveRelayURL(from: args)

    if revokeSelf && !confirm {
        fputs("CAUTION: Revoking this Mac's identity permanently disables it until 'wipe' + re-pair.\n", stderr)
        fputs("Re-run with '--self --confirm' to revoke this Mac on the VPS.\n", stderr)
        exit(2)
    }

    do {
        let sessionToken = try await client.authenticate(vpsBaseURL: vpsURL, identity: identity)
        var targetDeviceID = explicitDevice

        if targetDeviceID == nil && !revokeSelf {
            let status = try await client.getDeviceStatus(vpsBaseURL: vpsURL, sessionToken: sessionToken)
            if status.isPaired, let peerID = status.peerDeviceId, !peerID.isEmpty {
                targetDeviceID = peerID
            } else {
                if isJSON {
                    printJSON([
                        "status": "ERROR",
                        "error_message": "No paired peer device found. Specify --device <id> or pass --self --confirm."
                    ])
                } else {
                    fputs("ERROR: No paired Android device found on VPS. Specify --device <id> or use '--self --confirm'.\n", stderr)
                }
                exit(1)
            }
        }

        if let peerToRevoke = targetDeviceID {
            try await client.revokeDevice(vpsBaseURL: vpsURL, deviceID: peerToRevoke, sessionToken: sessionToken)
        }
        if revokeSelf {
            try await client.revokeDevice(vpsBaseURL: vpsURL, deviceID: identity.deviceID, sessionToken: sessionToken)
            identity.wipeIdentity()
        }

        if isJSON {
            printJSON([
                "status": "OK",
                "revoked_device_id": targetDeviceID ?? identity.deviceID,
                "revoked_self": revokeSelf
            ])
        } else {
            if let revokedPeer = targetDeviceID {
                print("SUCCESS: Device \(revokedPeer) revoked on VPS with immediate effect.")
            }
            if revokeSelf {
                print("SUCCESS: Local Mac identity revoked on VPS and wiped from Keychain.")
            }
        }
        exit(0)
    } catch {
        if isJSON {
            printJSON([
                "status": "ERROR",
                "error_message": error.localizedDescription
            ])
        } else {
            fputs("ERROR: Revocation failed: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
}

func handleStatus(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isWatch = parseFlag("--watch", in: args)
    let vpsURL = resolveRelayURL(from: args)

    if isWatch {
        let manager = ConnectionManager(
            vpsBaseURL: vpsURL,
            identity: identity,
            authClient: client,
            urlSession: client.configuredURLSession
        )
        if !isJSON {
            print("Connecting to PhoneLink Relay at \(vpsURL)...")
            print("Listening for real-time presence events (Press Ctrl+C to stop)")
            print("--------------------------------------------------")
            fflush(stdout)
        }

        manager.onStateChange = { newState in
            let dateStr = Date().ISO8601Format()
            func emitJSON(_ dict: [String: Any]) {
                if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]),
                   let str = String(data: data, encoding: .utf8) {
                    print(str)
                    fflush(stdout)
                }
            }
            switch newState {
            case .peerOnline(let id):
                if isJSON {
                    emitJSON(["timestamp": dateStr, "event": "PEER_ONLINE", "peer_device_id": id, "is_online": true])
                } else {
                    print("[\(dateStr)] Phone is ONLINE (\(id))")
                    fflush(stdout)
                }
            case .peerOffline(let id):
                if isJSON {
                    emitJSON(["timestamp": dateStr, "event": "PEER_OFFLINE", "peer_device_id": id, "is_online": false])
                } else {
                    print("[\(dateStr)] Phone is OFFLINE (\(id))")
                    fflush(stdout)
                }
            case .reconnecting(let attempt, let delaySeconds):
                if isJSON {
                    emitJSON(["timestamp": dateStr, "event": "RECONNECTING", "attempt": attempt, "delay_seconds": delaySeconds])
                } else {
                    print(String(format: "[\(dateStr)] Reconnecting (attempt #%d in %.1fs)...", attempt, delaySeconds))
                    fflush(stdout)
                }
            case .error(let msg):
                if isJSON {
                    emitJSON(["timestamp": dateStr, "event": "ERROR", "message": msg])
                } else {
                    print("[\(dateStr)] Error: \(msg)")
                    fflush(stdout)
                }
            default:
                break
            }
        }

        await manager.connectWithAutoReconnect()

        while true {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    } else {
        let startTime = Date()
        let manager = ConnectionManager(
            vpsBaseURL: vpsURL,
            identity: identity,
            authClient: client,
            urlSession: client.configuredURLSession
        )
        let finalState = await manager.connectAndWaitForPresence(timeoutSeconds: 2.0)
        let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
        manager.disconnect()

        let isConnected = manager.state.isConnected || finalState.isConnected
        var peerOnline = false
        var peerID = "Unknown"

        if case .peerOnline(let id) = finalState {
            peerOnline = true
            peerID = id
        } else if case .peerOffline(let id) = finalState {
            peerOnline = false
            peerID = id
        }

        if isJSON {
            let dict: [String: Any] = [
                "relay_connected": isConnected,
                "peer_online": peerOnline,
                "peer_device_id": peerID,
                "latency_ms": latencyMs,
                "state": "\(finalState)"
            ]
            printJSON(dict)
        } else {
            print("PhoneLink Status Report")
            print("--------------------------------------------------")
            print("VPS Relay:      \(isConnected ? "Connected (OK)" : "Unreachable / Disconnected")")
            print("Paired Phone:   \(peerOnline ? "ONLINE" : "OFFLINE") (\(peerID))")
            print("Query Latency:  \(latencyMs) ms")
        }
        exit(0)
    }
}

func handlePing(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isRelayOnly = parseFlag("--relay", in: args)
    let isDevice = parseFlag("--device", in: args)
    let count = parseStrictIntOption("--count", in: args, default: 1, min: 1, max: 100)
    let vpsURL = resolveRelayURL(from: args)
    let vpsStr = vpsURL.absoluteString

    if isDevice || !isRelayOnly {
        let duration = parseStrictUInt32Option("--duration", in: args, default: 5, min: 1, max: 30, clampWithNote: true)
        var latencies: [Int] = []
        var lastResp: DevicePingResponse? = nil

        do {
            for seq in 1...count {
                let startTime = Date()
                let resp = try await ActionClient.sendPing(
                    vpsBaseURL: vpsURL,
                    identity: identity,
                    client: client,
                    durationSeconds: duration
                )
                let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
                latencies.append(latencyMs)
                lastResp = resp
                if !isJSON && count > 1 {
                    print("[\(seq)/\(count)] Device Ping status=\(resp.status) rtt=\(latencyMs)ms")
                }
            }

            if let resp = lastResp {
                let avgRtt = latencies.reduce(0, +) / max(1, latencies.count)
                if isJSON {
                    var dict: [String: Any] = [
                        "request_id": resp.requestId,
                        "status": resp.status,
                        "duration_seconds": duration,
                        "message": resp.message,
                        "rtt_ms": avgRtt,
                        "count": count
                    ]
                    if count > 1 {
                        dict["rtts_ms"] = latencies
                    }
                    printJSON(dict)
                } else if count == 1 {
                    print("PhoneLink Device Ping Response")
                    print("--------------------------------------------------")
                    print("Status:       \(resp.status)")
                    print("Duration:     \(duration)s")
                    print("Message:      \(resp.message)")
                    print("Roundtrip:    \(latencies[0]) ms")
                } else {
                    print("Completed \(count) pings (avg=\(avgRtt)ms)")
                }
                exit(resp.status == "STATUS_OK" ? 0 : 1)
            }
        } catch {
            if isRelayOnly {
                // fall through to relay ping
            } else {
                fputs("ERROR: Failed to ping Android device: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
    }

    var relayLatencies: [Int] = []
    for seq in 1...count {
        let manager = ConnectionManager(
            vpsBaseURL: vpsURL,
            identity: identity,
            authClient: client,
            urlSession: client.configuredURLSession
        )
        let startTime = Date()
        await manager.connect()

        let finalState = manager.state
        let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
        manager.disconnect()

        guard finalState.isConnected else {
            let errMsg: String
            if case .error(let m) = finalState { errMsg = m } else { errMsg = "Relay unreachable (\(finalState))" }
            if isJSON {
                printJSON([
                    "status": "ERROR",
                    "target": vpsStr,
                    "error": errMsg
                ])
            } else {
                fputs("ERROR: Relay ping to [\(vpsStr)] failed: \(errMsg)\n", stderr)
            }
            exit(1)
        }
        relayLatencies.append(latencyMs)
        if !isJSON && count > 1 {
            print("Ping to PhoneLink VPS [\(vpsStr)] seq=\(seq)/\(count): time=\(latencyMs)ms status=OK")
        }
    }

    let avgLatency = relayLatencies.reduce(0, +) / max(1, relayLatencies.count)
    if isJSON {
        var dict: [String: Any] = [
            "status": "OK",
            "rtt_ms": avgLatency,
            "target": vpsStr,
            "count": count
        ]
        if count > 1 {
            dict["rtts_ms"] = relayLatencies
        }
        printJSON(dict)
    } else if count == 1 {
        print("Ping to PhoneLink VPS [\(vpsStr)]: time=\(relayLatencies[0])ms status=OK")
    } else {
        print("Completed \(count) relay pings to [\(vpsStr)] (avg=\(avgLatency)ms)")
    }
    exit(0)
}

func handleDevice(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    guard let sub = args.first else {
        print("""
        USAGE: phonelink device <action> [options]
        
        ACTIONS:
          info          Retrieve remote phone telemetry (model, OS, battery, storage)
          ping          Trigger remote phone audio/vibration ping (max 30s)
        
        OPTIONS:
          --duration <s duration in seconds for ping (1..30, default: 5)
          --vps <url>   Override VPS relay URL
          --json        Format output as JSON
        """)
        exit(2)
    }
    let restArgs = Array(args.dropFirst())
    switch sub {
    case "info":
        var infoArgs = restArgs
        infoArgs.append("--device")
        await handleInfo(args: infoArgs, identity: identity, client: client)
    case "ping":
        var pingArgs = restArgs
        pingArgs.append("--device")
        await handlePing(args: pingArgs, identity: identity, client: client)
    default:
        fputs("ERROR: Unknown device action '\(sub)'. Only allowlisted actions (info, ping) are permitted.\n", stderr)
        exit(2)
    }
}

func printFilesUsage() {
    print("""
    USAGE: phonelink files <subcommand> [options]

    SUBCOMMANDS:
      ls [path]       List files in the remote scoped directory (default: "")
      get <path>      Download file from remote phone (FILE-3)
      put <path>      Upload file to remote phone (FILE-4)

    OPTIONS:
      --vps <url>     Override VPS relay URL (default: \(Config.defaultRelayURL))
      --json          Format output as JSON
      -h, --help      Show help information

    EXAMPLES:
      phonelink files ls
      phonelink files ls Documents
      phonelink files ls --json
      phonelink files get Documents/report.pdf
      phonelink files get Documents/report.pdf ./my_report.pdf
      phonelink files put ./local_file.pdf Documents
      phonelink files put ./photo.jpg
    """)
}

func handleFiles(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isHelp = parseFlag("-h", in: args) || parseFlag("--help", in: args)

    if args.isEmpty || isHelp {
        printFilesUsage()
        exit(0)
    }

    let positional = parsePositionalArgs(in: args, valuedOptions: ["--vps", "--tls-pin", "--timeout"])
    guard let fileSubcommand = positional.first else {
        printFilesUsage()
        exit(2)
    }
    var remainingArgs = args
    if let subIdx = remainingArgs.firstIndex(of: fileSubcommand) {
        remainingArgs.remove(at: subIdx)
    }

    switch fileSubcommand {
    case "ls", "list":
        await handleFilesList(args: remainingArgs, identity: identity, client: client, isJSON: isJSON)
    case "get", "download":
        await handleFilesGet(args: remainingArgs, identity: identity, client: client, isJSON: isJSON)
    case "put", "upload":
        await handleFilesPut(args: remainingArgs, identity: identity, client: client, isJSON: isJSON)
    default:
        fputs("ERROR: Unknown files subcommand '\(fileSubcommand)'. Run 'phonelink files --help' for usage.\n", stderr)
        exit(2)
    }
}

func handleFilesPut(args: [String], identity: DeviceIdentityManager, client: AuthClient, isJSON: Bool) async {
    let vpsURL = resolveRelayURL(from: args)
    let timeout = parseFiniteDoubleOption("--timeout", in: args, default: 60.0, min: 1.0, max: 86_400.0)

    // Positional arguments: <local_path> [remote_destination_directory]
    let positionalArgs = parsePositionalArgs(in: args, valuedOptions: ["--vps", "--tls-pin", "--timeout"])

    guard let localPath = positionalArgs.first, !localPath.isEmpty else {
        fputs("ERROR: Missing required <local_path> argument. Run 'phonelink files put <local_path> [remote_directory]'\n", stderr)
        exit(2)
    }

    let localURL = URL(fileURLWithPath: localPath)
    var srcIsDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: localURL.path, isDirectory: &srcIsDir) else {
        fputs("ERROR: Local source file does not exist: \(localURL.path)\n", stderr)
        exit(1)
    }
    if srcIsDir.boolValue {
        fputs("ERROR: Local source path is a directory, expected a file: \(localURL.path)\n", stderr)
        exit(2)
    }

    let remoteDirectory = positionalArgs.count > 1 ? positionalArgs[1] : ""
    let fileName = localURL.lastPathComponent

    if !isJSON {
        let targetDisplay = remoteDirectory.isEmpty ? fileName : "\(remoteDirectory)/\(fileName)"
        print("Connecting to Android device via relay...")
        print("Uploading: \(localURL.path) -> Android:/\(targetDisplay)")
    }

    let startTime = Date()
    do {
        let result = try await FileClient.uploadLocalFile(
            vpsBaseURL: vpsURL,
            identity: identity,
            client: client,
            localSourceURL: localURL,
            remoteDestinationDirectory: remoteDirectory,
            remoteFileName: fileName,
            timeoutSeconds: timeout,
            progressHandler: { progress in
                if !isJSON {
                    let line = FileClient.formatTransferProgressLine(
                        bytesTransferred: progress.bytesTransferred,
                        totalBytes: progress.totalBytes,
                        bytesPerSecond: progress.bytesPerSecond
                    )
                    fputs(line, stdout)
                    fflush(stdout)
                }
            }
        )

        let elapsed = max(0.001, Date().timeIntervalSince(startTime))
        if !isJSON {
            print("\n--------------------------------------------------")
            print("SUCCESS: File upload complete.")
            print("Remote File:      \(remoteDirectory.isEmpty ? "" : remoteDirectory + "/")\(fileName)")
            print("Size:             \(FileClient.formatByteSize(result.bytesTransferred)) (\(result.bytesTransferred) bytes)")
            print("Verified SHA-256: \(result.sha256)")
            print(String(format: "Elapsed Time:     %.2f s", elapsed))
        } else {
            let dict: [String: Any] = [
                "status": "OK",
                "local_path": localURL.path,
                "remote_directory": remoteDirectory,
                "file_name": fileName,
                "bytes_transferred": result.bytesTransferred,
                "size_formatted": FileClient.formatByteSize(result.bytesTransferred),
                "sha256": result.sha256,
                "elapsed_seconds": (Double(Int(elapsed * 1000)) / 1000.0)
            ]
            printJSON(dict)
        }
        exit(0)
    } catch {
        if !isJSON {
            fputs("\nERROR: Upload failed: \(error.localizedDescription)\n", stderr)
        } else {
            printJSON([
                "status": "ERROR",
                "local_path": localURL.path,
                "error_message": error.localizedDescription
            ])
        }
        exit(1)
    }
}

func handleFilesGet(args: [String], identity: DeviceIdentityManager, client: AuthClient, isJSON: Bool) async {
    let vpsURL = resolveRelayURL(from: args)

    let noResume = parseFlag("--no-resume", in: args)
    let timeout = parseFiniteDoubleOption("--timeout", in: args, default: 60.0, min: 1.0, max: 86_400.0)

    // Positional arguments: remote_path and optional local_path
    let positionalArgs = parsePositionalArgs(in: args, valuedOptions: ["--vps", "--tls-pin", "--timeout"])

    guard let remotePath = positionalArgs.first, !remotePath.isEmpty else {
        fputs("ERROR: Missing required <path> argument. Run 'phonelink files get <path> [local_path]'\n", stderr)
        exit(2)
    }

    let localDestinationPath: String
    if positionalArgs.count > 1 {
        localDestinationPath = positionalArgs[1]
    } else {
        let filename = (remotePath as NSString).lastPathComponent
        guard !filename.isEmpty && filename != "." && filename != ".." && filename != "/" else {
            fputs("ERROR: Cannot derive local filename from '\(remotePath)'; pass explicit [local_path].\n", stderr)
            exit(2)
        }
        localDestinationPath = (FileManager.default.currentDirectoryPath as NSString).appendingPathComponent(filename)
    }

    let localURL = URL(fileURLWithPath: localDestinationPath)
    var destIsDir: ObjCBool = false
    if FileManager.default.fileExists(atPath: localURL.path, isDirectory: &destIsDir), destIsDir.boolValue {
        fputs("ERROR: Local destination is an existing directory: \(localURL.path)\n", stderr)
        exit(2)
    }

    if !isJSON {
        print("Connecting to Android device via relay...")
        print("Downloading: \(remotePath) -> \(localURL.path)")
    }

    let startTime = Date()
    do {
        let result = try await FileClient.downloadRemoteFile(
            vpsBaseURL: vpsURL,
            identity: identity,
            client: client,
            remotePath: remotePath,
            localDestinationURL: localURL,
            allowResume: !noResume,
            timeoutSeconds: timeout,
            progressHandler: { progress in
                if !isJSON {
                    let line = FileClient.formatTransferProgressLine(
                        bytesTransferred: progress.bytesTransferred,
                        totalBytes: progress.totalBytes,
                        bytesPerSecond: progress.bytesPerSecond
                    )
                    fputs(line, stdout)
                    fflush(stdout)
                }
            }
        )

        let elapsed = max(0.001, Date().timeIntervalSince(startTime))
        if !isJSON {
            print("\n--------------------------------------------------")
            print("SUCCESS: File download complete.")
            print("Local Path:       \(localURL.path)")
            print("Size:             \(FileClient.formatByteSize(result.bytesTransferred)) (\(result.bytesTransferred) bytes)")
            print("Verified SHA-256: \(result.sha256)")
            print(String(format: "Elapsed Time:     %.2f s", elapsed))
        } else {
            let dict: [String: Any] = [
                "status": "OK",
                "remote_path": remotePath,
                "local_path": localURL.path,
                "bytes_transferred": result.bytesTransferred,
                "size_formatted": FileClient.formatByteSize(result.bytesTransferred),
                "sha256": result.sha256,
                "elapsed_seconds": (Double(Int(elapsed * 1000)) / 1000.0)
            ]
            printJSON(dict)
        }
        exit(0)
    } catch {
        if !isJSON {
            fputs("\nERROR: Download failed: \(error.localizedDescription)\n", stderr)
        } else {
            printJSON([
                "status": "ERROR",
                "remote_path": remotePath,
                "error_message": error.localizedDescription
            ])
        }
        exit(1)
    }
}

func handleFilesList(args: [String], identity: DeviceIdentityManager, client: AuthClient, isJSON: Bool) async {
    let vpsURL = resolveRelayURL(from: args)

    // Extract target directory path (first option-aware positional argument)
    let targetPath = parsePositionalArgs(in: args, valuedOptions: ["--vps", "--tls-pin", "--timeout"]).first ?? ""

    do {
        let response = try await FileClient.listRemoteFiles(
            vpsBaseURL: vpsURL,
            identity: identity,
            client: client,
            targetDirectory: targetPath,
            timeoutSeconds: 8.0
        )

        if response.status != "STATUS_OK" {
            let errMsg = response.errorMessage ?? "Unknown remote error"
            if isJSON {
                printJSON([
                    "status": "ERROR",
                    "error_code": response.status,
                    "error_message": errMsg,
                    "directory": targetPath
                ])
            } else {
                fputs("ERROR: Remote file listing failed (\(response.status)): \(errMsg)\n", stderr)
            }
            exit(1)
        }

        if isJSON {
            let itemDicts: [[String: Any]] = response.items.map { item in
                [
                    "name": item.name,
                    "path": item.path,
                    "is_directory": item.isDirectory,
                    "size_bytes": item.sizeBytes,
                    "size_formatted": FileClient.formatByteSize(item.sizeBytes),
                    "modified_time": item.modifiedTime,
                    "modified_formatted": FileClient.formatDate(item.modifiedTime),
                    "mime_type": item.mimeType
                ]
            }

            let dict: [String: Any] = [
                "status": "OK",
                "current_directory": response.currentDirectory.isEmpty ? "/" : "/\(response.currentDirectory)",
                "count": response.items.count,
                "items": itemDicts
            ]
            printJSON(dict)
        } else {
            for line in FileClient.formatFileListLines(response) {
                print(line)
            }
        }
        exit(0)
    } catch {
        if isJSON {
            printJSON([
                "status": "ERROR",
                "error": error.localizedDescription
            ])
        } else {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
}

// MARK: - Camera Stream & Viewer Command (CAM-3 / CAM-4)

func handleCamera(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isHelp = parseFlag("-h", in: args) || parseFlag("--help", in: args)

    if isHelp {
        print("""
        Usage: phonelink camera [view|stream] [options]

        Live camera viewer and preview stream client for paired Android device.

        COMMANDS:
          view                  Interactive live terminal viewer with visual canvas (default)
          stream                Stream log mode with real-time frame transmission metrics

        OPTIONS:
          --lens <front|back>   Select camera lens (default: back)
          --fps <1-5>           Target frame rate (default: 2)
          --quality <10-100>    JPEG compression quality (default: 80)
          --duration <sec>      Maximum streaming duration (default: 10s)
          --max-frames <n>      Stop after receiving n frames
          --save <directory>    Save received JPEG frames to specified directory
          --no-canvas           Disable visual ASCII canvas in view mode
          --vps <url>           VPS relay URL override
          --json                Output stream stats in JSON format
        """)
        exit(0)
    }

    let valuedOpts: Set<String> = ["--lens", "--fps", "--quality", "--duration", "--max-frames", "--save", "--vps", "--tls-pin"]
    let positional = parsePositionalArgs(in: args, valuedOptions: valuedOpts)
    let mode = positional.first?.lowercased() ?? "view"
    if mode != "view" && mode != "stream" {
        fputs("ERROR: Unknown camera mode '\(mode)'. Expected 'view' or 'stream'. Run 'phonelink camera --help'.\n", stderr)
        exit(2)
    }
    let isViewMode = (mode == "view")
    let showCanvas = isViewMode && !parseFlag("--no-canvas", in: args)
    let saveDir = parseStrictOption("--save", in: args)

    let vpsURL = resolveRelayURL(from: args)

    var lens: CameraLens = .back
    if let lensStr = parseStrictOption("--lens", in: args)?.lowercased() {
        switch lensStr {
        case "front": lens = .front
        case "back": lens = .back
        default:
            fputs("ERROR: Invalid --lens '\(lensStr)'. Expected 'front' or 'back'.\n", stderr)
            exit(2)
        }
    }

    let targetFps = parseStrictUInt32Option("--fps", in: args, default: 2, min: 1, max: 5, clampWithNote: true)
    let jpegQuality = parseStrictUInt32Option("--quality", in: args, default: 80, min: 10, max: 100, clampWithNote: true)
    let durationSeconds = parseFiniteDoubleOption("--duration", in: args, default: 10.0, min: 1.0, max: 300.0, clampWithNote: true)
    let maxFrames = parseStrictUInt64Option("--max-frames", in: args, min: 1)

    let maxWidth: UInt32 = 1280
    let maxHeight: UInt32 = 720

    // Prepare save directory if requested
    var saveURL: URL? = nil
    if let dir = saveDir {
        let url = URL(fileURLWithPath: (dir as NSString).expandingTildeInPath)
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            saveURL = url
        } catch {
            fputs("ERROR: Failed to create save directory '\(url.path)': \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    let viewerController = CameraViewerController()
    viewerController.notifyConnecting()
    let renderLock = NSLock()
    let isInteractiveTTY = isatty(STDOUT_FILENO) == 1

    if !isJSON {
        print(CameraTerminalRenderer.renderBanner(state: viewerController.state, lens: lens, width: maxWidth, height: maxHeight))
        if showCanvas {
            print(CameraTerminalRenderer.renderAsciiCanvas(frame: nil, state: viewerController.state))
        }
    }

    let targetSaveURL = saveURL
    let activeLens = lens
    let control = CameraStreamControl()

    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
    sigintSource.setEventHandler { control.requestStop(reason: "user_interrupted") }
    sigintSource.resume()
    let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    sigtermSource.setEventHandler { control.requestStop(reason: "terminated") }
    sigtermSource.resume()

    func cleanupSignals() {
        sigintSource.cancel()
        sigtermSource.cancel()
        signal(SIGINT, SIG_DFL)
        signal(SIGTERM, SIG_DFL)
    }

    let staleWatchdogTask: Task<Void, Never>? = (!isJSON && showCanvas) ? Task {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 250_000_000)
            guard !Task.isCancelled else { break }
            if viewerController.checkStale() {
                renderLock.withLock {
                    let banner = CameraTerminalRenderer.renderBanner(state: viewerController.state, lens: activeLens)
                    let canvas = CameraTerminalRenderer.renderAsciiCanvas(frame: nil, state: viewerController.state)
                    let prefix = isInteractiveTTY ? "\u{001B}[H\u{001B}[2J" : "\n"
                    print(prefix + banner + "\n" + canvas)
                    fflush(stdout)
                }
            }
        }
    } : nil

    do {
        let summary = try await CameraClient.streamCamera(
            vpsBaseURL: vpsURL,
            identity: identity,
            client: client,
            lens: activeLens,
            targetFps: targetFps,
            jpegQuality: jpegQuality,
            maxWidth: maxWidth,
            maxHeight: maxHeight,
            maxDurationSeconds: durationSeconds,
            maxFrames: maxFrames,
            control: control,
            onFrame: { frame, stats in
                viewerController.notifyFrameReceived(frame: frame, stats: stats)

                // Save frame if requested
                if let sUrl = targetSaveURL {
                    let frameFilename = String(format: "frame_%05llu.jpg", frame.frameNumber)
                    let fileURL = sUrl.appendingPathComponent(frameFilename)
                    try? frame.jpegData.write(to: fileURL)
                }

                if !isJSON {
                    renderLock.withLock {
                        if showCanvas {
                            let banner = CameraTerminalRenderer.renderBanner(
                                state: viewerController.state,
                                lens: activeLens,
                                width: frame.width,
                                height: frame.height,
                                frameBytes: frame.jpegData.count
                            )
                            let canvas = CameraTerminalRenderer.renderAsciiCanvas(frame: frame, state: viewerController.state)
                            let prefix = isInteractiveTTY ? "\u{001B}[H\u{001B}[2J" : "\n"
                            print(prefix + banner + "\n" + canvas)
                            fflush(stdout)
                        } else {
                            let sizeKB = Double(frame.jpegData.count) / 1024.0
                            print(String(format: "[Frame #%llu] %ux%u (%.1f KB) | Latency: %lld ms | Rate: %.1f FPS",
                                         frame.frameNumber, frame.width, frame.height, sizeKB, stats.lastLatencyMs, stats.currentFps))
                            fflush(stdout)
                        }
                    }
                }
            },
            onStatusChange: { status in
                if !isJSON && !showCanvas {
                    renderLock.withLock {
                        print(">> \(status)")
                        fflush(stdout)
                    }
                }
            }
        )

        staleWatchdogTask?.cancel()
        viewerController.notifyStopped(reason: summary.stopReason)

        if isJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted]
            let data = try encoder.encode(summary)
            if let str = String(data: data, encoding: .utf8) {
                print(str)
            }
        } else {
            renderLock.withLock {
                if showCanvas {
                    let banner = CameraTerminalRenderer.renderBanner(
                        state: viewerController.state,
                        lens: lens,
                        width: maxWidth,
                        height: maxHeight
                    )
                    let canvas = CameraTerminalRenderer.renderAsciiCanvas(frame: nil, state: viewerController.state)
                    let prefix = isInteractiveTTY ? "\u{001B}[H\u{001B}[2J" : "\n"
                    print(prefix + banner + "\n" + canvas)
                }
                print("--------------------------------------------------------------------------------")
                print("Viewer state: \(viewerController.state.statusBadge) - \(viewerController.state.statusDescription)")
                print("Stream summary: \(summary.totalFrames) frames received, \(summary.droppedFrames) dropped")
                print(String(format: "Average Latency: %.1f ms | Average Rate: %.1f FPS | Duration: %.2f s",
                             summary.averageLatencyMs, summary.averageFps, summary.durationSeconds))
                print("Status: \(summary.stopReason)")
            }
        }
        cleanupSignals()
        exit(0)
    } catch {
        staleWatchdogTask?.cancel()
        viewerController.notifyError(message: error.localizedDescription)
        if isJSON {
            printJSON([
                "status": "ERROR",
                "error": error.localizedDescription
            ])
        } else {
            print(CameraTerminalRenderer.renderBanner(state: viewerController.state, lens: lens))
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
        }
        cleanupSignals()
        exit(1)
    }
}

// MARK: - Microphone Audio Stream & Recorder Command

private final class MicOutputCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private let saveURL: URL?
    private let enablePlayback: Bool
    private var wavWriter: MicWavWriter? = nil
    private var livePlayer: MicLivePlayer? = nil
    private var writeErrorMessage: String? = nil

    init(saveURL: URL?, enablePlayback: Bool) {
        self.saveURL = saveURL
        self.enablePlayback = enablePlayback
    }

    func configure(sampleRateHz: UInt32, channels: UInt32, bitsPerSample: UInt32) -> (wavError: String?, playbackWarning: String?) {
        lock.withLock {
            var wavErr: String? = nil
            var playWarn: String? = nil
            let clampedCh = UInt16(min(8, max(1, channels)))
            let safeBits: UInt16 = bitsPerSample == 8 ? 8 : 16

            if let url = saveURL {
                do {
                    wavWriter = try MicWavWriter(
                        url: url,
                        sampleRateHz: sampleRateHz,
                        channels: clampedCh,
                        bitsPerSample: safeBits
                    )
                } catch {
                    wavErr = error.localizedDescription
                    writeErrorMessage = wavErr
                }
            }

            if enablePlayback {
                let player = MicLivePlayer(sampleRateHz: sampleRateHz, channels: UInt32(clampedCh))
                if let warn = player.startupErrorMessage {
                    playWarn = warn
                }
                if player.isAvailable {
                    livePlayer = player
                }
            }
            return (wavErr, playWarn)
        }
    }

    func writeAndPlay(pcmData: Data) -> String? {
        let (writer, player) = lock.withLock { (wavWriter, livePlayer) }
        var errMsg: String? = nil
        if let writer {
            do {
                try writer.append(pcmData: pcmData)
            } catch {
                lock.withLock {
                    if writeErrorMessage == nil {
                        writeErrorMessage = error.localizedDescription
                    }
                    errMsg = writeErrorMessage
                }
            }
        }
        player?.enqueue(pcmData: pcmData)
        return errMsg
    }

    @discardableResult
    func finishAll() -> (bytes: UInt64, writeError: String?) {
        let (writer, player, prevErr) = lock.withLock {
            let w = wavWriter
            let p = livePlayer
            let e = writeErrorMessage
            wavWriter = nil
            livePlayer = nil
            return (w, p, e)
        }
        player?.drainAndStop(maxWaitMs: 600)
        let bytes = writer?.finalize() ?? 0
        let finalErr = prevErr ?? writer?.lastFinalizeError
        return (bytes, finalErr)
    }
}

func handleMic(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isHelp = parseFlag("-h", in: args) || parseFlag("--help", in: args)

    if isHelp {
        print("""
        Usage: phonelink mic [listen|record] [options]

        Stream live encrypted PCM audio from paired Android phone microphone or save to WAV.

        COMMANDS:
          listen                Stream live audio to Mac speakers (default; supports --save)
          record                Save audio directly to a WAV file without speaker playback

        OPTIONS:
          --rate <8000-48000>   Target sample rate in Hz (default: 16000)
          --duration <sec>      Maximum streaming duration in seconds (default: 15, max: 300)
          --max-chunks <n>      Stop after receiving n audio chunks
          --save <file.wav>     Save audio stream to a WAV file
          --no-play             Disable live Mac speaker playback in listen mode
          --vps <url>           VPS relay URL override
          --tls-pin <hash>      Require SHA-256 SPKI pin on HTTPS/WSS connections
          --json                Output stream summary as JSON
        """)
        exit(0)
    }

    let positional = parsePositionalArgs(in: args, valuedOptions: ["--rate", "--duration", "--max-chunks", "--save", "--vps", "--tls-pin"])
    let mode = positional.first?.lowercased() ?? "listen"
    if mode != "listen" && mode != "record" {
        fputs("ERROR: Unknown mic mode '\(mode)'. Expected 'listen' or 'record'. Run 'phonelink mic --help'.\n", stderr)
        exit(2)
    }

    let isRecordMode = (mode == "record")
    let enablePlayback = !isRecordMode && !parseFlag("--no-play", in: args)

    let vpsURL = resolveRelayURL(from: args)
    let sampleRateHz = parseStrictUInt32Option("--rate", in: args, default: 16000, min: 8000, max: 48000, clampWithNote: true)
    let durationSeconds = parseFiniteDoubleOption("--duration", in: args, default: 15.0, min: 1.0, max: 300.0, clampWithNote: true)
    let maxChunks = parseStrictUInt64Option("--max-chunks", in: args, min: 1)

    var saveURL: URL? = nil
    if let saveOpt = parseStrictOption("--save", in: args), !saveOpt.isEmpty {
        saveURL = URL(fileURLWithPath: (saveOpt as NSString).expandingTildeInPath)
    } else if isRecordMode {
        let ts = Int(Date().timeIntervalSince1970)
        saveURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("phonelink_mic_\(ts).wav")
    }

    let output = MicOutputCoordinator(saveURL: saveURL, enablePlayback: enablePlayback)
    let control = MicStreamControl()

    // Ensure Ctrl+C / SIGTERM stops Android mic cleanly and finalizes WAV RIFF header
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
    sigintSource.setEventHandler { control.requestStop(reason: "user_interrupted") }
    sigintSource.resume()
    let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    sigtermSource.setEventHandler { control.requestStop(reason: "terminated") }
    sigtermSource.resume()

    func cleanupSignals() {
        sigintSource.cancel()
        sigtermSource.cancel()
        signal(SIGINT, SIG_DFL)
        signal(SIGTERM, SIG_DFL)
    }

    if !isJSON {
        print("PhoneLink Remote Microphone (\(mode.uppercased()))")
        print("--------------------------------------------------")
        if let path = saveURL?.path {
            print("Recording WAV: \(path)")
        }
        print("Live Playback: \(enablePlayback ? "Enabled (Mac Speakers)" : "Disabled")")
    }

    do {
        let summary = try await MicClient.streamMic(
            vpsBaseURL: vpsURL,
            identity: identity,
            client: client,
            sampleRateHz: sampleRateHz,
            channels: 1,
            chunkDurationMs: 200,
            maxDurationSeconds: durationSeconds,
            maxChunks: maxChunks,
            control: control,
            onStarted: { startResp in
                let result = output.configure(
                    sampleRateHz: startResp.actualSampleRateHz > 0 ? startResp.actualSampleRateHz : sampleRateHz,
                    channels: startResp.actualChannels > 0 ? startResp.actualChannels : 1,
                    bitsPerSample: startResp.bitsPerSample > 0 ? startResp.bitsPerSample : 16
                )
                if let wavErr = result.wavError {
                    fputs("ERROR: Failed to initialize WAV output: \(wavErr)\n", stderr)
                    if isRecordMode {
                        control.requestStop(reason: "wav_init_failed")
                    }
                }
                if let playWarn = result.playbackWarning, enablePlayback && !isJSON {
                    fputs("WARN: Audio playback unavailable (\(playWarn)); continuing stream without speaker output.\n", stderr)
                }
            },
            onChunk: { chunk, stats in
                if let writeErr = output.writeAndPlay(pcmData: chunk.pcmData) {
                    fputs("\nERROR: WAV write failed: \(writeErr)\n", stderr)
                    if isRecordMode {
                        control.requestStop(reason: "wav_write_failed")
                    }
                }
                if !isJSON {
                    let kb = Double(stats.bytesReceived) / 1024.0
                    let line = String(
                        format: "\r\u{001B}[K● LIVE MIC | Chunk #%llu | %.1f KB | Rate: %.1f kbps | Latency: %lld ms (Ctrl+C to stop)",
                        stats.chunksReceived, kb, stats.rateKbps, stats.lastLatencyMs
                    )
                    fputs(line, stdout)
                    fflush(stdout)
                }
            },
            onStatusChange: { status in
                if !isJSON {
                    print("\n>> \(status)")
                }
            }
        )

        let finished = output.finishAll()
        if let wavErr = finished.writeError, isRecordMode || saveURL != nil {
            if isJSON {
                printJSON([
                    "status": "ERROR",
                    "error": "WAV recording failed: \(wavErr)"
                ])
            } else {
                fputs("\nERROR: WAV recording failed: \(wavErr)\n", stderr)
            }
            cleanupSignals()
            exit(1)
        }

        if isJSON {
            var dict: [String: Any] = [
                "status": "OK",
                "session_id": summary.sessionId,
                "total_chunks": summary.totalChunks,
                "dropped_chunks": summary.droppedChunks,
                "total_bytes": summary.totalBytes,
                "sample_rate_hz": summary.actualSampleRateHz,
                "channels": summary.actualChannels,
                "bits_per_sample": summary.bitsPerSample,
                "average_latency_ms": summary.averageLatencyMs,
                "duration_seconds": summary.durationSeconds,
                "stop_reason": summary.stopReason
            ]
            if let path = saveURL?.path {
                dict["saved_wav_path"] = path
                dict["saved_pcm_bytes"] = finished.bytes
            }
            printJSON(dict)
        } else {
            print("\n--------------------------------------------------")
            print("Microphone stream stopped (\(summary.stopReason)).")
            print("Format:          \(summary.actualSampleRateHz) Hz mono, \(summary.bitsPerSample)-bit PCM")
            print("Chunks Received: \(summary.totalChunks) (dropped: \(summary.droppedChunks))")
            print("Audio Received:  \(FileClient.formatByteSize(summary.totalBytes))")
            print(String(format: "Average Latency: %.1f ms | Duration: %.2f s", summary.averageLatencyMs, summary.durationSeconds))
            if let path = saveURL?.path {
                print("Saved WAV File:  \(path)")
            }
        }
        cleanupSignals()
        exit(0)
    } catch {
        _ = output.finishAll()
        if isJSON {
            printJSON([
                "status": "ERROR",
                "error": error.localizedDescription
            ])
        } else {
            fputs("\nERROR: \(error.localizedDescription)\n", stderr)
        }
        cleanupSignals()
        exit(1)
    }
}

func resolveInstallerScriptPath() -> String? {
    var candidates: [String] = [
        "./scripts/serve_phone_installer.py",
        "../scripts/serve_phone_installer.py",
        "../../scripts/serve_phone_installer.py",
        "/opt/phonelink/scripts/serve_phone_installer.py"
    ]
    if let envRoot = ProcessInfo.processInfo.environment["PHONELINK_REPO_ROOT"], !envRoot.isEmpty {
        candidates.insert(URL(fileURLWithPath: envRoot).appendingPathComponent("scripts/serve_phone_installer.py").path, at: 0)
    }
    // Check ancestors of resolved executable path (e.g. mac/.build/release/phonelink)
    if let arg0 = CommandLine.arguments.first {
        var dir = URL(fileURLWithPath: arg0).resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0..<6 {
            candidates.append(dir.appendingPathComponent("scripts/serve_phone_installer.py").path)
            dir = dir.deletingLastPathComponent()
        }
    }
    // Source checkout relative fallback from mac/Sources/PhoneLinkCLI/main.swift
    let repoFromSource = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // PhoneLinkCLI
        .deletingLastPathComponent() // Sources
        .deletingLastPathComponent() // mac
        .deletingLastPathComponent() // PhoneLink repo root
    candidates.append(repoFromSource.appendingPathComponent("scripts/serve_phone_installer.py").path)

    for path in candidates {
        if FileManager.default.fileExists(atPath: path) {
            return path
        }
    }
    return nil
}

func handleInstallPhone(args: [String]) {
    let isJSON = parseFlag("--json", in: args)
    let vpsURL = resolveRelayURL(from: args)
    let port = parseStrictIntOption("--port", in: args, default: 8080, min: 1, max: 65535)

    // Construct clean install URL on VPS
    var installComps = URLComponents(url: vpsURL, resolvingAgainstBaseURL: false) ?? URLComponents()
    installComps.query = nil
    installComps.fragment = nil
    let basePath = installComps.path.hasSuffix("/") ? String(installComps.path.dropLast()) : installComps.path
    if let wsRange = basePath.range(of: "/ws/", options: .caseInsensitive) {
        installComps.path = String(basePath[..<wsRange.lowerBound]) + "/install"
    } else {
        installComps.path = basePath + "/install"
    }
    let vpsInstallUrl = installComps.url?.absoluteString ?? "\(vpsURL.absoluteString)/install"

    if parseFlag("--serve", in: args) || parseFlag("--local", in: args) {
        guard let script = resolveInstallerScriptPath() else {
            if isJSON {
                printJSON(["status": "ERROR", "error": "Could not locate scripts/serve_phone_installer.py"])
            } else {
                fputs("ERROR: Could not locate scripts/serve_phone_installer.py.\n", stderr)
                fputs("Set PHONELINK_REPO_ROOT=/path/to/PhoneLink or run from the PhoneLink repo root.\n", stderr)
            }
            exit(1)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", script, "--port", String(port)]
        do {
            try process.run()
            process.waitUntilExit()
            exit(process.terminationStatus)
        } catch {
            if isJSON {
                printJSON(["status": "ERROR", "error": error.localizedDescription])
            } else {
                fputs("ERROR: Failed to launch installer server: \(error.localizedDescription)\n", stderr)
            }
            exit(1)
        }
    }

    if isJSON {
        printJSON([
            "vps_install_url": vpsInstallUrl,
            "min_sdk": 26,
            "target_sdk": 34,
            "supported_os": "Android 8.0 Oreo through Android 14+",
            "apk_download_endpoint": "/download/PhoneLink.apk"
        ])
        exit(0)
    }

    print("""
    ================================================================================
      📱 PhoneLink 1-Tap Over-The-Air (OTA) Phone Installer
    ================================================================================
    Universal Android Build (minSdk 26: Android 8.0 Oreo through Android 14+)

    1. Via VPS Web Endpoint:
       Open this link directly in Chrome on your phone to tap & install:
       👉 \(vpsInstallUrl)

    2. Via Local Wi-Fi (No Internet / LAN):
       Run with '--local' to spin up a local web server with a terminal QR code:
       👉 phonelink install-phone --local

    3. Direct APK File:
       ./android/release/PhoneLink-v1.0.0-release.apk (2.1 MB)
    ================================================================================
    """)
    exit(0)
}

// MARK: - Main Execution

signal(SIGPIPE, SIG_IGN)

let args = CommandLine.arguments

if args.count <= 1 {
    printUsage()
    exit(0)
}

let command = args[1]
let subArgs = Array(args.dropFirst(2))
let identity = DeviceIdentityManager.shared
let tlsPin = Config.resolvePinnedSHA256(args: subArgs)
let client = AuthClient(urlSession: PinnedURLSessionDelegate.makeSession(pinnedSHA256: tlsPin))

switch command {
case "-v", "--version", "version":
    print(PhoneLinkInfo.banner())
    exit(0)

case "-h", "--help", "help":
    printUsage()
    exit(0)

case "info":
    await handleInfo(args: subArgs, identity: identity, client: client)

case "device":
    await handleDevice(args: subArgs, identity: identity, client: client)

case "wipe":
    handleWipe(args: subArgs, identity: identity)

case "pair":
    await handlePair(args: subArgs, identity: identity, client: client)

case "revoke":
    await handleRevoke(args: subArgs, identity: identity, client: client)

case "status":
    await handleStatus(args: subArgs, identity: identity, client: client)

case "ping":
    await handlePing(args: subArgs, identity: identity, client: client)

case "files":
    await handleFiles(args: subArgs, identity: identity, client: client)

case "camera":
    await handleCamera(args: subArgs, identity: identity, client: client)

case "mic":
    await handleMic(args: subArgs, identity: identity, client: client)

case "install", "install-phone":
    handleInstallPhone(args: subArgs)

default:
    fputs("ERROR: Unknown subcommand '\(command)'. Run 'phonelink --help' for usage.\n", stderr)
    exit(2)
}
