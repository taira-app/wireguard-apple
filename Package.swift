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
            dependencies: ["BoringTunFFI"],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
        .target(
            name: "BoringTunFFI",
            dependencies: [],
            exclude: [
                "Makefile"
            ],
            publicHeadersPath: ".",
            linkerSettings: [
                .linkedLibrary("boringtun")
            ]
        ),
        .testTarget(
            name: "WireGuardTests",
            dependencies: ["WireGuard"]
        )
    ]
)
