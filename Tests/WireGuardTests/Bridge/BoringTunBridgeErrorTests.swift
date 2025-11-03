// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import XCTest

@testable import WireGuard

/// Tests for BoringTunBridge actor and its FFI integration.
///
/// BoringTunBridge is the primary interface to BoringTun's Rust implementation.
/// These tests verify:
/// - Tunnel creation with valid and invalid keys
/// - Tunnel destruction and cleanup
/// - Statistics retrieval
/// - Error handling for operations without active tunnel
/// - Actor isolation and thread safety
///
/// Note: These are integration tests that call actual BoringTun FFI functions,
/// so they test both our Swift wrapper and BoringTun's behavior.
final class BoringTunBridgeErrorTests: XCTestCase {
	// MARK: - Test keys

	// Valid base64-encoded x25519 keys for testing.
	// These are test keys and should never be used in production.

	/// Valid x25519 private key (32 bytes base64-encoded).
	///
	/// This is a randomly generated test key. In production, keys should be
	/// generated securely using BoringTun's key generation or CryptoKit.
	private let validPrivateKey = "yAnz5TF+lXXJte14tji3zlMNftXnCjZVe15vOlSk+28="

	/// Valid x25519 public key (32 bytes base64-encoded).
	///
	/// This is the peer's public key for the test tunnel. It corresponds to
	/// a different private key (not included here).
	private let validPeerPublicKey = "XIuO7t/0wFTL6xVX9EKC3RhTXq1hRWZnSC9oCTc8nD8="

	/// Valid pre-shared key (32 bytes base64-encoded).
	///
	/// This is optional additional symmetric key material for post-quantum security.
	private let validPresharedKey = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

	/// Invalid base64 string (not 32 bytes when decoded).
	private let invalidKey = "notavalidkey"

	// MARK: - Packet processing error tests

	/// Tests that packet processing fails without an active tunnel.
	///
	/// All packet processing methods should check for an active tunnel
	/// and throw invalidHandle if none exists.
	func testProcessOutboundPacketWithoutTunnel() async {
		let bridge = BoringTunBridge()

		// Try to process a packet without creating a tunnel
		let packet = Data([0x45, 0x00, 0x00, 0x54])  // Start of IPv4 packet
		var buffer = [UInt8](repeating: 0, count: 2048)

		do {
			_ = try await bridge.processOutboundPacket(packet, into: &buffer)
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests that inbound packet processing fails without an active tunnel.
	func testProcessInboundPacketWithoutTunnel() async {
		let bridge = BoringTunBridge()

		// Try to process a packet without creating a tunnel
		let packet = Data([0x01, 0x00, 0x00, 0x00])  // Start of WireGuard packet
		var buffer = [UInt8](repeating: 0, count: 2048)

		do {
			_ = try await bridge.processInboundPacket(packet, into: &buffer)
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests that tick() fails without an active tunnel.
	func testTickWithoutTunnel() async {
		let bridge = BoringTunBridge()

		var buffer = [UInt8](repeating: 0, count: 2048)

		do {
			_ = try await bridge.tick(into: &buffer)
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests that forceHandshake() fails without an active tunnel.
	func testForceHandshakeWithoutTunnel() async {
		let bridge = BoringTunBridge()

		var buffer = [UInt8](repeating: 0, count: 2048)

		do {
			_ = try await bridge.forceHandshake(into: &buffer)
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	// MARK: - Actor isolation tests

	/// Tests that the bridge can be accessed from multiple tasks concurrently.
	///
	/// The actor isolation ensures that even when multiple tasks try to access
	/// the bridge simultaneously, operations are serialized and thread-safe.
	/// This test verifies there are no data races or crashes.
	func testConcurrentAccess() async throws {
		let bridge = BoringTunBridge()

		// Create initial tunnel
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: nil,
			keepalive: 0
		)

		// Launch multiple concurrent tasks that access the bridge
		await withTaskGroup(of: Void.self) { group in
			// Task 1: Read statistics repeatedly
			group.addTask {
				for _ in 0..<10 {
					_ = try? await bridge.statistics()
				}
			}

			// Task 2: Call tick repeatedly
			group.addTask {
				var buffer = [UInt8](repeating: 0, count: 2048)
				for _ in 0..<10 {
					_ = try? await bridge.tick(into: &buffer)
				}
			}

			// Task 3: Read statistics again
			group.addTask {
				for _ in 0..<10 {
					_ = try? await bridge.statistics()
				}
			}

			// Wait for all tasks to complete
			await group.waitForAll()
		}

		// Bridge should still be functional
		let finalStats = try await bridge.statistics()
		XCTAssertEqual(finalStats.timeSinceLastHandshake, -1)
	}
}
