# WireGuard Swift

Modern Swift implementation of the WireGuard protocol for Apple platforms.

## Overview

WireGuard Swift provides a Swift 6 interface for implementing WireGuard VPN functionality on macOS and iOS. The library is designed for building VPN clients and network security applications with full support for modern Swift concurrency features.

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

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the package
swift build

# Run tests
swift test
```

## Requirements

- Swift 6.0 or later
- Rust toolchain (for building BoringTun)
- Xcode 16.0 or later (for iOS/macOS development)

## License

See LICENSE.txt for details.
