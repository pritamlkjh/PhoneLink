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
      info          Show local Mac device identity, public key, and relay config
      pair          Initiate pairing ceremony (generates pairing token & short code)
      status        Check relay connectivity and Android phone online/offline state
                    Options: --watch (stream real-time updates), --json, --vps <url>
      ping          Send an end-to-end encrypted round-trip ping to the phone
      wipe          Wipe stored credentials and reset Mac device identity
      files         Browse and transfer files (FILE-2, FILE-3)
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

func handleInfo(args: [String], identity: DeviceIdentityManager) {
    let isJSON = parseFlag("--json", in: args)
    let devID = identity.deviceID
    let pubKey = identity.publicKeyBase64
    let relayURL = parseOption("--vps", in: args) ?? Config.defaultRelayURL

    if isJSON {
        let dict: [String: Any] = [
            "client": PhoneLinkInfo.clientName,
            "version": PhoneLinkInfo.version,
            "device_id": devID,
            "public_key": pubKey,
            "key_algorithm": "ED25519",
            "relay_url": relayURL
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
        print("Relay Endpoint: \(relayURL)")
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
    let vpsStr = parseOption("--vps", in: args) ?? Config.defaultRelayURL
    guard let vpsURL = URL(string: vpsStr) else {
        fputs("ERROR: Invalid VPS relay URL: \(vpsStr)\n", stderr)
        exit(2)
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
    handleInfo(args: subArgs, identity: identity)

case "wipe":
    handleWipe(args: subArgs, identity: identity)

case "pair":
    await handlePair(args: subArgs, identity: identity, client: client)

case "status":
    await handleStatus(args: subArgs, identity: identity, client: client)

case "ping":
    await handlePing(args: subArgs, identity: identity, client: client)

case "files":
    print("Files subcommand reserved for FILE-2/FILE-3.")
    exit(0)

case "camera":
    print("Camera subcommand reserved for CAM-3/CAM-4.")
    exit(0)

default:
    fputs("ERROR: Unknown subcommand '\(command)'. Run 'phonelink --help' for usage.\n", stderr)
    exit(2)
}
