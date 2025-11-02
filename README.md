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

- macOS 13.0 or later
- iOS 15.0 or later

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

### Build BoringTun static library

Before building the Swift package, you must build the BoringTun static library:

```bash
# Build for macOS (current architecture)
cd Sources/BoringTunFFI
make build

# Or build for specific architectures
make build ARCHS="arm64 x86_64"

# Clean build artifacts
make clean
```

This creates `Sources/BoringTunFFI/out/libboringtun.a` which the Swift package will link against.

### Build Swift package

```bash
# Build the Swift package
swift build

# Run tests
swift test

# Run linter
swiftlint

# Format code
swift-format --recursive --in-place Sources Tests
```

## Requirements

- Swift 6.0 or later
- Rust toolchain (for building BoringTun)
- Xcode 16.0 or later (for iOS/macOS development)

## License

This project is dual-licensed under your choice of:

- **LGPL-3.0-only**: Free for open source use. Derivative works must also be licensed under LGPL-3.0.
- **Commercial License**: For proprietary or closed-source applications. Contact licensing@taira.cloud for terms.

See `LICENSES/` directory for full license texts.
