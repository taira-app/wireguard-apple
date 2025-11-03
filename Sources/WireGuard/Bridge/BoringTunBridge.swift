// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation

/// Thread-safe Swift wrapper for BoringTun's C FFI.
///
/// This actor provides the primary interface between Swift code and BoringTun's
/// Rust implementation. It wraps all BoringTun FFI functions with:
/// - Thread safety via Swift's actor isolation
/// - Memory safety through proper lifecycle management
/// - Type safety using Swift types instead of raw C pointers
/// - Error handling with Swift errors instead of null/error codes
///
/// ## Architecture
///
/// BoringTunBridge owns a single WireGuard tunnel instance (the C `wireguard_tunnel`
/// pointer) and provides async methods for all operations on that tunnel. The actor
/// ensures that only one operation executes at a time, preventing race conditions
/// and use-after-free bugs.
///
/// ## Lifecycle
///
/// 1. **Creation**: Initialize with `createTunnel()` - allocates tunnel in Rust
/// 2. **Operation**: Call packet processing and stats methods
/// 3. **Destruction**: Automatically freed in `deinit` or explicit `destroyTunnel()`
///
/// ## Examples
///
/// ```swift
/// let bridge = BoringTunBridge()
/// try await bridge.createTunnel(
///     privateKey: "yAnz5TF+lXXJte14tji3zlMNftXnCjZVe15vOlSk+28=",
///     peerPublicKey: "XIuO7hH0wFTL6xVX9EKC3RhTXq1hRWZnSC9oCTc8nD8=",
///     presharedKey: nil,
///     keepalive: 25
/// )
///
/// // Process outbound packet
/// var outputBuffer = [UInt8](repeating: 0, count: 65536)
/// let result = try await bridge.processOutboundPacket(
///     ipPacket,
///     into: &outputBuffer
/// )
/// ```
public actor BoringTunBridge {
	/// The BoringTun tunnel handle.
	///
	/// This is an opaque pointer to BoringTun's internal tunnel state, allocated
	/// by `new_tunnel()` and freed by `tunnel_free()`. The pointer is managed
	/// exclusively by this actor - external code never sees it.
	///
	/// A nil value indicates no tunnel is currently active. All packet processing
	/// operations require a non-nil handle.
	///
	/// Marked `nonisolated(unsafe)` to allow access from `deinit`. This is safe
	/// because the handle is only accessed from actor-isolated methods during
	/// normal operation, and `deinit` only runs when no other references exist.
	nonisolated(unsafe) internal var tunnelHandle: OpaquePointer?

	/// Creates a new BoringTun bridge instance.
	///
	/// The bridge starts with no active tunnel. Call `createTunnel()` to initialize
	/// a tunnel before performing packet operations.
	public init() {
		self.tunnelHandle = nil
	}

	/// Creates a new WireGuard tunnel instance.
	///
	/// This allocates a new tunnel in BoringTun's Rust code by calling `new_tunnel()`.
	/// The tunnel is configured with the provided cryptographic keys and keepalive
	/// settings.
	///
	/// If a tunnel already exists, it is automatically destroyed before creating
	/// the new one, ensuring no resource leaks.
	///
	/// ## Parameters
	///
	/// - Parameter privateKey: This device's x25519 private key (base64-encoded)
	/// - Parameter peerPublicKey: The peer's x25519 public key (base64-encoded)
	/// - Parameter presharedKey: Optional pre-shared key for additional security (base64-encoded)
	/// - Parameter keepalive: Persistent keepalive interval in seconds, or 0 to disable
	///
	/// ## Keepalive
	///
	/// WireGuard uses keepalives to maintain NAT mappings and detect dead peers.
	/// Typical values:
	/// - **0**: Disabled (for server-side or stable networks)
	/// - **25**: Recommended for mobile clients behind NAT
	/// - **120+**: Maximum useful value (handshake rekey occurs at 120s anyway)
	///
	/// ## Throws
	///
	/// - `BridgeError.tunnelCreationFailed`: BoringTun returned null, indicating
	///   invalid keys, memory allocation failure, or internal error
	///
	/// ## Example
	///
	/// ```swift
	/// try await bridge.createTunnel(
	///     privateKey: privateKeyBase64,
	///     peerPublicKey: peerPublicKeyBase64,
	///     presharedKey: nil,  // Optional
	///     keepalive: 25       // 25 seconds for mobile
	/// )
	/// ```
	public func createTunnel(
		privateKey: String,
		peerPublicKey: String,
		presharedKey: String?,
		keepalive: UInt16
	) throws {
		// Destroy any existing tunnel first to prevent resource leaks
		if tunnelHandle != nil {
			destroyTunnel()
		}

		// Call BoringTun's new_tunnel FFI function.
		// This returns an opaque pointer to the Rust tunnel structure, or null on error.
		// The index parameter is for tracking multiple peers - we use 0 for single-peer tunnels.
		tunnelHandle = privateKey.withCString { privateKeyPtr in
			peerPublicKey.withCString { peerPublicKeyPtr in
				if let preshared = presharedKey {
					return preshared.withCString { presharedPtr in
						new_tunnel(privateKeyPtr, peerPublicKeyPtr, presharedPtr, keepalive, 0)
					}
				} else {
					return new_tunnel(privateKeyPtr, peerPublicKeyPtr, nil, keepalive, 0)
				}
			}
		}

		// Verify the tunnel was created successfully
		guard tunnelHandle != nil else {
			throw BridgeError.tunnelCreationFailed
		}
	}

	/// Destroys the active tunnel and frees its resources.
	///
	/// This calls BoringTun's `tunnel_free()` to deallocate the Rust tunnel
	/// structure. After this call, the bridge has no active tunnel and cannot
	/// process packets until `createTunnel()` is called again.
	///
	/// It's safe to call this multiple times - if no tunnel exists, it does nothing.
	/// The tunnel is also automatically destroyed in `deinit`.
	public func destroyTunnel() {
		guard let handle = tunnelHandle else { return }

		// Call BoringTun's FFI function to free the tunnel.
		// This deallocates all Rust memory associated with the tunnel.
		tunnel_free(handle)
		tunnelHandle = nil
	}

	/// Cleans up resources when the bridge is deallocated.
	///
	/// This ensures the tunnel is properly freed even if the caller forgets to
	/// explicitly call `destroyTunnel()`. Swift's deinit is called automatically
	/// when the last reference to this actor is released.
	deinit {
		// Free the tunnel if it still exists.
		// We can't call destroyTunnel() here because deinit isn't async,
		// but we can directly call the C function since we're in the actor.
		if let handle = tunnelHandle {
			tunnel_free(handle)
		}
	}

	/// Retrieves current tunnel statistics.
	///
	/// This calls BoringTun's `wireguard_stats()` to get metrics about the tunnel's
	/// operation, including handshake timing, data transfer, and network quality.
	///
	/// ## Returns
	///
	/// A `TunnelStatistics` struct containing:
	/// - Time since last handshake
	/// - Bytes transmitted and received
	/// - Estimated packet loss and RTT
	///
	/// ## Throws
	///
	/// - `BridgeError.invalidHandle`: No tunnel is currently active
	///
	/// ## Example
	///
	/// ```swift
	/// let stats = try await bridge.statistics()
	/// print("Transmitted: \(stats.transmittedBytes) bytes")
	/// print("RTT: \(stats.estimatedRTT)ms")
	/// ```
	public func statistics() throws -> TunnelStatistics {
		guard let handle = tunnelHandle else {
			throw BridgeError.invalidHandle
		}

		// Call BoringTun's wireguard_stats() which returns a C struct
		let cStats = wireguard_stats(handle)

		// Convert the C struct to our Swift type
		return TunnelStatistics(cStats: cStats)
	}
}
