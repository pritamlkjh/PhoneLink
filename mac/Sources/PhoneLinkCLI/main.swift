import Foundation
import PhoneLinkKit

struct CLI {
    static func printUsage() {
        print("""
        OVERVIEW: PhoneLink — Personal authorized remote-access system for macOS and Android.
        
        USAGE: phonelink <subcommand> [options]
        
        SUBCOMMANDS:
          status        Check connection status of relay and paired Android device
          pair          Initiate QR-code / short-code pairing ceremony with Android phone
          files         Browse, download, or upload files to/from Android phone
          camera        Start authorized live camera preview session
          ping          Trigger locate sound on paired Android device
          info          Retrieve telemetry and status from Android phone
          revoke        Revoke authorization of paired Android device
        
        OPTIONS:
          --version, -v Show PhoneLink version information
          --help, -h    Show help information
        """)
    }
    
    static func run() {
        let args = CommandLine.arguments
        
        if args.count <= 1 {
            printUsage()
            exit(0)
        }
        
        let command = args[1]
        
        switch command {
        case "--version", "-v", "version":
            print(PhoneLinkInfo.banner())
            exit(0)
            
        case "--help", "-h", "help":
            printUsage()
            exit(0)
            
        case "status":
            print("[\(PhoneLinkInfo.clientName)] Checking status...")
            print("Relay Status: Not connected (Configuration pending)")
            print("Android Device: Disconnected")
            exit(0)
            
        case "pair":
            print("[\(PhoneLinkInfo.clientName)] Initializing pairing ceremony...")
            print("Pairing protocol initialized (ARCH-2).")
            exit(0)
            
        default:
            fputs("Unknown command: '\(command)'. Run 'phonelink --help' for usage.\n", stderr)
            exit(1)
        }
    }
}

CLI.run()
