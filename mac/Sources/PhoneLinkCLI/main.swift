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
        if let cliPin = parseOption("--tls-pin", in: args), !cliPin.isEmpty {
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

func parseOption(_ option: String, in args: [String]) -> String? {
    if let idx = args.firstIndex(of: option), idx + 1 < args.count {
        return args[idx + 1]
    }
    return nil
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
        if arg.hasPrefix("-") {
            if arg.contains("=") {
                i += 1
                continue
            }
            i += 1
            continue
        }
        result.append(arg)
        i += 1
    }
    return result
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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL

    if isDevice {
        guard let vpsURL = URL(string: vpsStr) else {
            fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
            exit(2)
        }
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
                if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
                   let str = String(data: data, encoding: .utf8) {
                    print(str)
                }
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
                if let err = resp.errorMessage, !err.isEmpty {
                    print("Error:             \(err)")
                }
            }
            exit(resp.status == "STATUS_OK" ? 0 : 1)
        } catch {
            fputs("ERROR: Failed to fetch remote device info: \(error.localizedDescription)\n", stderr)
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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

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
    let explicitDevice = parseOption("--device", in: args)
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

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
        }

        manager.onStateChange = { newState in
            let dateStr = Date().formatted(.iso8601)
            switch newState {
            case .peerOnline(let id):
                if isJSON {
                    print("{\"timestamp\":\"\(dateStr)\",\"event\":\"PEER_ONLINE\",\"peer_device_id\":\"\(id)\",\"is_online\":true}")
                    fflush(stdout)
                } else {
                    print("[\(dateStr)] Phone is ONLINE (\(id))")
                }
            case .peerOffline(let id):
                if isJSON {
                    print("{\"timestamp\":\"\(dateStr)\",\"event\":\"PEER_OFFLINE\",\"peer_device_id\":\"\(id)\",\"is_online\":false}")
                    fflush(stdout)
                } else {
                    print("[\(dateStr)] Phone is OFFLINE (\(id))")
                }
            case .error(let msg):
                if isJSON {
                    print("{\"timestamp\":\"\(dateStr)\",\"event\":\"ERROR\",\"message\":\"\(msg)\"}")
                    fflush(stdout)
                } else {
                    print("[\(dateStr)] Error: \(msg)")
                }
            default:
                break
            }
        }

        await manager.connect()

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
    let count = max(1, Int(parseOption("--count", in: args) ?? "1") ?? 1)
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    if isDevice || !isRelayOnly {
        let durationStr = parseOption("--duration", in: args) ?? "5"
        let duration = UInt32(durationStr) ?? 5
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

        let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
        manager.disconnect()
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

    let fileSubcommand = args[0]
    let remainingArgs = Array(args.dropFirst())

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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    let timeoutStr = parseOption("--timeout", in: args)
    let timeout = Double(timeoutStr ?? "60.0") ?? 60.0

    // Positional arguments: <local_path> [remote_destination_directory]
    let positionalArgs = parsePositionalArgs(in: args, valuedOptions: ["--vps", "--tls-pin", "--timeout"])

    guard let localPath = positionalArgs.first, !localPath.isEmpty else {
        fputs("ERROR: Missing required <local_path> argument. Run 'phonelink files put <local_path> [remote_directory]'\n", stderr)
        exit(2)
    }

    let localURL = URL(fileURLWithPath: localPath)
    guard FileManager.default.fileExists(atPath: localURL.path) else {
        fputs("ERROR: Local source file does not exist: \(localURL.path)\n", stderr)
        exit(1)
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
            let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
            print(String(data: data, encoding: .utf8)!)
        }
        exit(0)
    } catch {
        if !isJSON {
            fputs("\nERROR: Upload failed: \(error.localizedDescription)\n", stderr)
        } else {
            let dict: [String: Any] = [
                "status": "ERROR",
                "local_path": localURL.path,
                "error_message": error.localizedDescription
            ]
            if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
                print(String(data: data, encoding: .utf8)!)
            }
        }
        exit(1)
    }
}

func handleFilesGet(args: [String], identity: DeviceIdentityManager, client: AuthClient, isJSON: Bool) async {
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    let noResume = parseFlag("--no-resume", in: args)
    let timeoutStr = parseOption("--timeout", in: args)
    let timeout = Double(timeoutStr ?? "60.0") ?? 60.0

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
        let filename = URL(fileURLWithPath: remotePath).lastPathComponent
        localDestinationPath = (FileManager.default.currentDirectoryPath as NSString).appendingPathComponent(filename)
    }

    let localURL = URL(fileURLWithPath: localDestinationPath)

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
            let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
            print(String(data: data, encoding: .utf8)!)
        }
        exit(0)
    } catch {
        if !isJSON {
            fputs("\nERROR: Download failed: \(error.localizedDescription)\n", stderr)
        } else {
            let dict: [String: Any] = [
                "status": "ERROR",
                "remote_path": remotePath,
                "error_message": error.localizedDescription
            ]
            if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
                print(String(data: data, encoding: .utf8)!)
            }
        }
        exit(1)
    }
}

func handleFilesList(args: [String], identity: DeviceIdentityManager, client: AuthClient, isJSON: Bool) async {
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

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
                let dict: [String: Any] = [
                    "status": "ERROR",
                    "error_code": response.status,
                    "error_message": errMsg,
                    "directory": targetPath
                ]
                let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
                print(String(data: data, encoding: .utf8)!)
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
            let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
            print(String(data: data, encoding: .utf8)!)
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

    let isViewMode = !args.contains("stream") // 'view' or default is view mode
    let showCanvas = isViewMode && !parseFlag("--no-canvas", in: args)
    let saveDir = parseOption("--save", in: args)

    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    var lens: CameraLens = .back
    if let lensStr = parseOption("--lens", in: args)?.lowercased() {
        if lensStr == "front" {
            lens = .front
        } else {
            lens = .back
        }
    }

    let fpsVal = UInt32(parseOption("--fps", in: args) ?? "2") ?? 2
    let targetFps = min(max(fpsVal, 1), 5)

    let qVal = UInt32(parseOption("--quality", in: args) ?? "80") ?? 80
    let jpegQuality = min(max(qVal, 10), 100)

    let dVal = Double(parseOption("--duration", in: args) ?? "10.0") ?? 10.0
    let durationSeconds = max(dVal, 1.0)

    var maxFrames: UInt64? = nil
    if let mfStr = parseOption("--max-frames", in: args), let mfVal = UInt64(mfStr) {
        maxFrames = mfVal
    }

    let maxWidth: UInt32 = 1280
    let maxHeight: UInt32 = 720

    // Prepare save directory if requested
    var saveURL: URL? = nil
    if let dir = saveDir {
        let url = URL(fileURLWithPath: (dir as NSString).expandingTildeInPath)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        saveURL = url
    }

    let viewerController = CameraViewerController()
    viewerController.notifyConnecting()

    if !isJSON {
        print(CameraTerminalRenderer.renderBanner(state: viewerController.state, lens: lens, width: maxWidth, height: maxHeight))
        if showCanvas {
            print(CameraTerminalRenderer.renderAsciiCanvas(frame: nil, state: viewerController.state))
        }
    }

    let targetSaveURL = saveURL
    let activeLens = lens

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
            onFrame: { frame, stats in
                viewerController.notifyFrameReceived(frame: frame, stats: stats)

                // Save frame if requested
                if let sUrl = targetSaveURL {
                    let frameFilename = String(format: "frame_%05llu.jpg", frame.frameNumber)
                    let fileURL = sUrl.appendingPathComponent(frameFilename)
                    try? frame.jpegData.write(to: fileURL)
                }

                if !isJSON {
                    if showCanvas {
                        // In interactive view mode, redraw banner and canvas
                        let banner = CameraTerminalRenderer.renderBanner(
                            state: viewerController.state,
                            lens: activeLens,
                            width: frame.width,
                            height: frame.height,
                            frameBytes: frame.jpegData.count
                        )
                        let canvas = CameraTerminalRenderer.renderAsciiCanvas(frame: frame, state: viewerController.state)
                        print("\u{001B}[H\u{001B}[2J" + banner + "\n" + canvas)
                    } else {
                        let sizeKB = Double(frame.jpegData.count) / 1024.0
                        print(String(format: "[Frame #%llu] %ux%u (%.1f KB) | Latency: %lld ms | Rate: %.1f FPS",
                                     frame.frameNumber, frame.width, frame.height, sizeKB, stats.lastLatencyMs, stats.currentFps))
                    }
                }
            },
            onStatusChange: { status in
                if !isJSON && !showCanvas {
                    print(">> \(status)")
                }
            }
        )

        // Stream deactivation - strictly transition viewer to inactive state (CAM-4 invariant)
        viewerController.notifyStopped(reason: summary.stopReason)

        if isJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted]
            let data = try encoder.encode(summary)
            print(String(data: data, encoding: .utf8)!)
        } else {
            if showCanvas {
                let banner = CameraTerminalRenderer.renderBanner(
                    state: viewerController.state,
                    lens: lens,
                    width: maxWidth,
                    height: maxHeight
                )
                let canvas = CameraTerminalRenderer.renderAsciiCanvas(frame: nil, state: viewerController.state)
                print("\u{001B}[H\u{001B}[2J" + banner + "\n" + canvas)
            }
            print("--------------------------------------------------------------------------------")
            print("Viewer state: \(viewerController.state.statusBadge) - \(viewerController.state.statusDescription)")
            print("Stream summary: \(summary.totalFrames) frames received, \(summary.droppedFrames) dropped")
            print(String(format: "Average Latency: %.1f ms | Average Rate: %.1f FPS | Duration: %.2f s",
                         summary.averageLatencyMs, summary.averageFps, summary.durationSeconds))
            print("Status: \(summary.stopReason)")
        }
        exit(0)
    } catch {
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

    init(saveURL: URL?, enablePlayback: Bool) {
        self.saveURL = saveURL
        self.enablePlayback = enablePlayback
    }

    func configure(sampleRateHz: UInt32, channels: UInt32, bitsPerSample: UInt32) -> (wavError: String?, playbackWarning: String?) {
        lock.withLock {
            var wavErr: String? = nil
            var playWarn: String? = nil

            if let url = saveURL {
                do {
                    wavWriter = try MicWavWriter(
                        url: url,
                        sampleRateHz: sampleRateHz,
                        channels: UInt16(max(1, channels)),
                        bitsPerSample: UInt16(max(8, bitsPerSample))
                    )
                } catch {
                    wavErr = error.localizedDescription
                }
            }

            if enablePlayback {
                let player = MicLivePlayer(sampleRateHz: sampleRateHz, channels: channels)
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

    func writeAndPlay(pcmData: Data) {
        let (writer, player) = lock.withLock { (wavWriter, livePlayer) }
        try? writer?.append(pcmData: pcmData)
        player?.enqueue(pcmData: pcmData)
    }

    @discardableResult
    func finishAll() -> UInt64 {
        let (writer, player) = lock.withLock {
            let w = wavWriter
            let p = livePlayer
            wavWriter = nil
            livePlayer = nil
            return (w, p)
        }
        player?.stop()
        return writer?.finalize() ?? 0
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

    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    let requestedRate = UInt32(parseOption("--rate", in: args) ?? "16000") ?? 16000
    let sampleRateHz = min(max(requestedRate, 8000), 48000)

    let rawDuration = Double(parseOption("--duration", in: args) ?? "15.0") ?? 15.0
    let durationSeconds = min(max(rawDuration, 1.0), 300.0)

    var maxChunks: UInt64? = nil
    if let mcStr = parseOption("--max-chunks", in: args), let mcVal = UInt64(mcStr) {
        maxChunks = mcVal
    }

    var saveURL: URL? = nil
    if let saveOpt = parseOption("--save", in: args), !saveOpt.isEmpty {
        saveURL = URL(fileURLWithPath: (saveOpt as NSString).expandingTildeInPath)
    } else if isRecordMode {
        let ts = Int(Date().timeIntervalSince1970)
        saveURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("phonelink_mic_\(ts).wav")
    }

    let output = MicOutputCoordinator(saveURL: saveURL, enablePlayback: enablePlayback)
    let control = MicStreamControl()

    // Ensure Ctrl+C stops Android mic cleanly and finalizes WAV RIFF header
    signal(SIGINT, SIG_IGN)
    let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
    sigintSource.setEventHandler {
        control.requestStop(reason: "user_interrupted")
    }
    sigintSource.resume()
    defer {
        sigintSource.cancel()
        signal(SIGINT, SIG_DFL)
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
                    fputs("WARN: Failed to initialize WAV output: \(wavErr)\n", stderr)
                }
                if let playWarn = result.playbackWarning, enablePlayback && !isJSON {
                    fputs("WARN: Audio playback unavailable (\(playWarn)); continuing stream without speaker output.\n", stderr)
                }
            },
            onChunk: { chunk, stats in
                output.writeAndPlay(pcmData: chunk.pcmData)
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

        let wavBytes = output.finishAll()

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
                dict["saved_pcm_bytes"] = wavBytes
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
    let vps = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    let portStr = parseOption("--port", in: args) ?? "8080"
    
    // Construct install URL on VPS
    var vpsInstallUrl = vps.replacingOccurrences(of: "ws://", with: "http://")
        .replacingOccurrences(of: "wss://", with: "https://")
    if let wsIdx = vpsInstallUrl.range(of: "/ws/") {
        vpsInstallUrl = String(vpsInstallUrl[..<wsIdx.lowerBound])
    }
    vpsInstallUrl = vpsInstallUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/install"

    if parseFlag("--serve", in: args) || parseFlag("--local", in: args) {
        guard let script = resolveInstallerScriptPath() else {
            fputs("ERROR: Could not locate scripts/serve_phone_installer.py.\n", stderr)
            fputs("Set PHONELINK_REPO_ROOT=/path/to/PhoneLink or run from the PhoneLink repo root.\n", stderr)
            exit(1)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [script, "--port", portStr]
        do {
            try process.run()
            process.waitUntilExit()
            exit(process.terminationStatus)
        } catch {
            fputs("ERROR: Failed to launch installer server: \(error.localizedDescription)\n", stderr)
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
