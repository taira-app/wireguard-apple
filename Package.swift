// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TairaWireGuard",
    platforms: [
        .macOS(.v13),
        .iOS(.v15)
    ],
    products: [
        .library(name: "TairaWireGuard", targets: ["WireGuard"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WireGuard",
            dependencies: ["BoringTun"],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
        .binaryTarget(
            name: "BoringTun",
            path: "BoringTun.xcframework"
        ),
        .testTarget(
            name: "WireGuardTests",
            dependencies: ["WireGuard"]
        )
    ]
)
