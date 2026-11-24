import Foundation
import PhoneLinkKit

/// MAC-4: PhoneLink Mac Command-Line Interface.
/// Exit Code Conventions:
///   0 = Success
///   1 = Operational / Network / Authentication error
///   2 = Usage / Argument parsing error

struct Config {
    static let defaultRelayURL = ProcessInfo.processInfo.environment["PHONELINK_RELAY_URL"] ?? "http://127.0.0.1:8443"
}

func printUsage() {
    print("""
    OVERVIEW: PhoneLink — Personal authorized remote-access system for macOS and Android.
    
    USAGE: phonelink <subcommand> [options]
    
    SUBCOMMANDS:
      info          Show local Mac device identity (use '--device' for remote phone info)
      device        Execute scoped remote actions on phone (info, ping)
      pair          Initiate pairing ceremony (generates pairing token & short code)
      status        Check relay connectivity and Android phone online/offline state
                    Options: --watch (stream real-time updates), --json, --vps <url>
      ping          Send an end-to-end encrypted round-trip ping to the phone
                    Options: --duration <seconds>, --relay (ping relay only), --json
      wipe          Wipe stored credentials and reset Mac device identity
      files         Browse and transfer files (FILE-2, FILE-3, FILE-4)
      camera        Live camera streaming and capture (CAM-3, CAM-4)
      version       Show PhoneLink version information
      help          Show help information
    
    OPTIONS:
      --vps <url>   Override VPS relay URL (default: \(Config.defaultRelayURL))
      --json        Format output as machine-readable JSON
      -h, --help    Show help information
      -v, --version Show version
    
    EXAMPLES:
      phonelink info
      phonelink pair --vps http://127.0.0.1:8443
      phonelink status --json
      phonelink ping --count 3
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
        // Register device if not yet registered
        try await client.registerDevice(vpsBaseURL: vpsURL, identity: identity)

        // Generate one-time pairing token
        let token = try await client.createPairingToken(vpsBaseURL: vpsURL, deviceID: identity.deviceID)
        let shortCode = String(token.prefix(8)).uppercased()

        if isJSON {
            let dict: [String: Any] = [
                "status": "OK",
                "device_id": identity.deviceID,
                "pairing_token": token,
                "short_code": shortCode,
                "expires_in_seconds": 300
            ]
            let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
            print(String(data: data, encoding: .utf8)!)
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

func handleStatus(args: [String], identity: DeviceIdentityManager, client: AuthClient) async {
    let isJSON = parseFlag("--json", in: args)
    let isWatch = parseFlag("--watch", in: args)
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    if isWatch {
        let manager = ConnectionManager(vpsBaseURL: vpsURL, identity: identity, authClient: client)
        if !isJSON {
            print("Connecting to PhoneLink Relay at \(vpsURL)...")
            print("Listening for real-time presence events (Press Ctrl+C to stop)")
            print("--------------------------------------------------")
        }

        manager.onStateChange = { newState in
            let dateStr = ISO8601DateFormatter().string(from: Date())
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
        let manager = ConnectionManager(vpsBaseURL: vpsURL, identity: identity, authClient: client)
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
            let data = try! JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
            print(String(data: data, encoding: .utf8)!)
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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
    }

    if isDevice || !isRelayOnly {
        let durationStr = parseOption("--duration", in: args) ?? "5"
        let duration = UInt32(durationStr) ?? 5
        let startTime = Date()

        do {
            let resp = try await ActionClient.sendPing(
                vpsBaseURL: vpsURL,
                identity: identity,
                client: client,
                durationSeconds: duration
            )
            let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)

            if isJSON {
                let dict: [String: Any] = [
                    "request_id": resp.requestId,
                    "status": resp.status,
                    "duration_seconds": duration,
                    "message": resp.message,
                    "rtt_ms": latencyMs
                ]
                if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
                   let str = String(data: data, encoding: .utf8) {
                    print(str)
                }
            } else {
                print("PhoneLink Device Ping Response")
                print("--------------------------------------------------")
                print("Status:       \(resp.status)")
                print("Duration:     \(duration)s")
                print("Message:      \(resp.message)")
                print("Roundtrip:    \(latencyMs) ms")
            }
            exit(resp.status == "STATUS_OK" ? 0 : 1)
        } catch {
            if isRelayOnly {
                // fall through to relay ping
            } else {
                fputs("ERROR: Failed to ping Android device: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
    }

    let manager = ConnectionManager(vpsBaseURL: vpsURL, identity: identity, authClient: client)
    let startTime = Date()
    await manager.connect()

    let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
    manager.disconnect()

    if isJSON {
        let dict: [String: Any] = [
            "status": "OK",
            "rtt_ms": latencyMs,
            "target": vpsStr
        ]
        let data = try! JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
        print(String(data: data, encoding: .utf8)!)
    } else {
        print("Ping to PhoneLink VPS [\(vpsStr)]: time=\(latencyMs)ms status=OK")
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
    var positionalArgs: [String] = []
    var i = 0
    while i < args.count {
        let arg = args[i]
        if arg == "--vps" || arg == "--timeout" {
            i += 2
            continue
        }
        if arg.hasPrefix("-") {
            i += 1
            continue
        }
        positionalArgs.append(arg)
        i += 1
    }

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
        print("Connecting to Android device via relay...")
        print("Uploading: \(localURL.path) -> Android:/\(remoteDirectory)/\(fileName)")
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
                    let pct = progress.totalBytes > 0 ? (Double(progress.bytesTransferred) / Double(progress.totalBytes)) * 100.0 : 100.0
                    let transferredStr = FileClient.formatByteSize(progress.bytesTransferred)
                    let totalStr = FileClient.formatByteSize(progress.totalBytes)
                    let speedStr = FileClient.formatByteSize(UInt64(max(0, progress.bytesPerSecond))) + "/s"
                    let barWidth = 30
                    let completedChars = Int((pct / 100.0) * Double(barWidth))
                    let bar = String(repeating: "=", count: max(0, min(barWidth, completedChars))) +
                              (completedChars < barWidth ? ">" : "") +
                              String(repeating: " ", count: max(0, barWidth - completedChars - 1))
                    let line = String(format: "\r[%@] %5.1f%% (%@ / %@) %@", bar, pct, transferredStr, totalStr, speedStr)
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
    var positionalArgs: [String] = []
    var i = 0
    while i < args.count {
        let arg = args[i]
        if arg == "--vps" || arg == "--timeout" {
            i += 2
            continue
        }
        if arg.hasPrefix("-") {
            i += 1
            continue
        }
        positionalArgs.append(arg)
        i += 1
    }

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
                    let pct = progress.totalBytes > 0 ? (Double(progress.bytesTransferred) / Double(progress.totalBytes)) * 100.0 : 100.0
                    let transferredStr = FileClient.formatByteSize(progress.bytesTransferred)
                    let totalStr = FileClient.formatByteSize(progress.totalBytes)
                    let speedStr = FileClient.formatByteSize(UInt64(max(0, progress.bytesPerSecond))) + "/s"
                    let barWidth = 30
                    let completedChars = Int((pct / 100.0) * Double(barWidth))
                    let bar = String(repeating: "=", count: max(0, min(barWidth, completedChars))) +
                              (completedChars < barWidth ? ">" : "") +
                              String(repeating: " ", count: max(0, barWidth - completedChars - 1))
                    let line = String(format: "\r[%@] %5.1f%% (%@ / %@) %@", bar, pct, transferredStr, totalStr, speedStr)
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

    // Extract target directory path (first non-flag argument)
    var targetPath = ""
    for arg in args {
        if !arg.hasPrefix("-") {
            targetPath = arg
            break
        }
    }

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
            let dirDisplay = response.currentDirectory.isEmpty ? "/" : "/\(response.currentDirectory)"
            print("Remote Directory: \(dirDisplay) (\(response.items.count) item\(response.items.count == 1 ? "" : "s"))")
            print("--------------------------------------------------------------------------------")
            print(String(format: "%-5s %-12s %-20s %@", "TYPE", "SIZE", "MODIFIED", "NAME"))
            print("--------------------------------------------------------------------------------")

            for item in response.items {
                let typeStr = item.isDirectory ? "DIR" : "FILE"
                let sizeStr = item.isDirectory ? "-" : FileClient.formatByteSize(item.sizeBytes)
                let dateStr = FileClient.formatDate(item.modifiedTime)
                let nameStr = item.isDirectory ? "\(item.name)/" : item.name

                print(String(format: "%-5s %-12s %-20s %@", typeStr, sizeStr, dateStr, nameStr))
            }
            print("--------------------------------------------------------------------------------")
        }
        exit(0)
    } catch {
        if isJSON {
            let dict: [String: Any] = [
                "status": "ERROR",
                "error": error.localizedDescription
            ]
            let data = try! JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted])
            print(String(data: data, encoding: .utf8)!)
        } else {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
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
let client = AuthClient()

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

case "status":
    await handleStatus(args: subArgs, identity: identity, client: client)

case "ping":
    await handlePing(args: subArgs, identity: identity, client: client)

case "files":
    await handleFiles(args: subArgs, identity: identity, client: client)

case "camera":
    print("Camera subcommand reserved for CAM-3/CAM-4.")
    exit(0)

default:
    fputs("ERROR: Unknown subcommand '\(command)'. Run 'phonelink --help' for usage.\n", stderr)
    exit(2)
}
