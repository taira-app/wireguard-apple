# Taira WireGuard for Apple

Modern Swift implementation of the WireGuard protocol for Apple platforms.

## Overview

Taira Wireguard for Apple provides a Swift 6 interface for implementing WireGuard VPN functionality on macOS and iOS. The library is designed for building VPN clients and network security applications with full support for modern Swift concurrency features.

Primary use case is integration with NetworkExtension framework for creating packet tunnel providers on Apple platforms.

## Architecture

The library wraps BoringTun, Cloudflare's production-grade Rust implementation of the WireGuard protocol. BoringTun powers Cloudflare WARP across millions of iOS and macOS devices, providing a battle-tested foundation.

Key architectural components:

- **Swift 6 API layer**: Actor-based concurrency model with sendable types
- **BoringTun core**: Rust-based protocol implementation with zero runtime overhead
- **FFI bridge**: Minimal C interface for Swift-Rust interoperability
- **NetworkExtension integration**: Designed for packet tunnel provider implementation

## Platform support

Currently supported platforms:
- macOS 13.0 or later (ARM64 / Apple Silicon)
- iOS 15.0 or later (ARM64 device)

Platform support limitations:
- **iOS simulator**: Not currently supported due to BoringTun dependency build issues (see known issues below)
- **macOS Intel (x86_64)**: Not currently built in XCFramework but can be added if needed

## Building

The library requires Rust toolchain for building the BoringTun dependency.

### Prerequisites

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Rust targets for cross-compilation (iOS support)
rustup target add aarch64-apple-darwin     # macOS arm64
rustup target add x86_64-apple-darwin      # macOS x86_64
rustup target add aarch64-apple-ios        # iOS arm64
rustup target add x86_64-apple-ios         # iOS simulator x86_64
rustup target add aarch64-apple-ios-sim    # iOS simulator arm64
```

### Build BoringTun XCFramework

Before building the Swift package, you must build the BoringTun XCFramework:

```bash
# Build XCFramework for all supported platforms
cd Sources/BoringTunFFI
make build-xcframework

# Clean build artifacts
make clean
```

This creates `BoringTun.xcframework` containing static libraries for:
- macOS ARM64 (Apple Silicon)
- iOS ARM64 (device only)

**Note on iOS Simulator**: Simulator support is temporarily unavailable due to a build issue in the `ring` cryptography crate (a BoringTun dependency). The ring crate version 0.16.20 contains outdated build scripts that fail when targeting `aarch64-apple-ios-sim` with the error:

```
clang: error: unknown argument: '-arch arm64'
```

This is a known issue in BoringTun's dependency chain. Device builds work perfectly - only simulator builds are affected. Simulator support will be restored when BoringTun upgrades to a newer ring version with fixed build scripts, or when we implement a workaround.

### Build Swift package

```bash
# Build the Swift package
swift build

# Run tests
swift test

# Run linter
swiftlint lint --strict

# Format code
swift-format --recursive --in-place Sources Tests
```

## Requirements

- Swift 6.0 or later
- Rust toolchain (for building BoringTun)
- Xcode 16.0 or later (for iOS/macOS development)
- ARM64 device for iOS testing (simulator not currently supported)

## Known issues

### iOS simulator support

iOS simulator builds are currently unavailable due to a build failure in the `ring` crate (version 0.16.20), which is a dependency of BoringTun. The ring crate uses an outdated version of the `cc-rs` build dependency that fails when compiling for the iOS simulator target (`aarch64-apple-ios-sim`).

**Error**: `clang: error: unknown argument: '-arch arm64'`

**Root cause**: The ring 0.16.20 crate depends on an old version of cc-rs that has [a known issue](https://github.com/rust-lang/cc-rs/issues/711) with the aarch64-apple-ios-sim target. This was fixed in cc-rs 1.0.79+, but ring 0.16.20 hasn't updated its dependency.

**Workaround**: Use a physical iOS device for development and testing. All functionality works correctly on actual hardware.

**Resolution path**: This issue will be resolved when:
1. BoringTun upgrades to a newer version of ring (0.17+) that uses cc-rs 1.0.79 or later, or
2. We implement a build script workaround to patch ring's dependencies

Device builds for both macOS and iOS work perfectly - only simulator builds are affected.

## License

This project is dual-licensed under your choice of:

- **LGPL-3.0-only**: Free for any use, including proprietary applications. You can link this library to closed-source code. Only modifications to the library itself must be open sourced under LGPL-3.0. Your application code remains under your chosen license.

- **Commercial license**: Alternative licensing for organizations that prefer commercial terms. Contact us at taira.cloud/licensing for details.

See `LICENSE.txt` for the full LGPL-3.0 license text.
