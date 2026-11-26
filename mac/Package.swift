// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PhoneLinkMac",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "phonelink", targets: ["PhoneLinkCLI"]),
        .library(name: "PhoneLinkKit", targets: ["PhoneLinkKit"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "PhoneLinkKit",
            dependencies: [],
            path: "Sources/PhoneLinkKit"
        ),
        .executableTarget(
            name: "PhoneLinkCLI",
            dependencies: ["PhoneLinkKit"],
            path: "Sources/PhoneLinkCLI"
        ),
        .executableTarget(
            name: "PhoneLinkTests",
            dependencies: ["PhoneLinkKit"],
            path: "Tests/PhoneLinkTests"
        )
    ]
)
