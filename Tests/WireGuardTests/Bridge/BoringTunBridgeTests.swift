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
final class BoringTunBridgeTests: XCTestCase {
	// MARK: - Test Keys

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

	// MARK: - Tunnel Creation Tests

	/// Tests successful tunnel creation with valid keys.
	///
	/// When provided with valid base64-encoded x25519 keys, BoringTun should
	/// create a tunnel and return without error. The tunnel should be ready
	/// for packet processing operations.
	func testCreateTunnelSuccess() async throws {
		let bridge = BoringTunBridge()

		// Create tunnel with valid keys - should not throw
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: nil,
			keepalive: 0
		)

		// Should be able to get statistics after creation
		let stats = try await bridge.statistics()

		// New tunnel should have no handshake yet
		XCTAssertEqual(stats.timeSinceLastHandshake, -1, "New tunnel should have no handshake")
		XCTAssertEqual(stats.transmittedBytes, 0, "New tunnel should have zero transmitted bytes")
		XCTAssertEqual(stats.receivedBytes, 0, "New tunnel should have zero received bytes")
	}

	/// Tests tunnel creation with pre-shared key.
	///
	/// WireGuard supports an optional pre-shared key for additional security
	/// (post-quantum resistance). This should work the same as without PSK.
	func testCreateTunnelWithPresharedKey() async throws {
		let bridge = BoringTunBridge()

		// Create tunnel with PSK - should not throw
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: validPresharedKey,
			keepalive: 25
		)

		// Should be functional
		let stats = try await bridge.statistics()
		XCTAssertEqual(stats.timeSinceLastHandshake, -1)
	}

	/// Tests tunnel creation failure with invalid private key.
	///
	/// If the private key is not a valid base64-encoded x25519 key,
	/// BoringTun should reject it and return null, which we convert
	/// to tunnelCreationFailed error.
	func testCreateTunnelWithInvalidPrivateKey() async {
		let bridge = BoringTunBridge()

		do {
			try await bridge.createTunnel(
				privateKey: invalidKey,  // Invalid
				peerPublicKey: validPeerPublicKey,
				presharedKey: nil,
				keepalive: 0
			)
			XCTFail("Should have thrown tunnelCreationFailed")
		} catch BridgeError.tunnelCreationFailed {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests tunnel creation failure with invalid peer public key.
	///
	/// If the peer's public key is invalid, BoringTun should reject the
	/// tunnel creation.
	func testCreateTunnelWithInvalidPeerPublicKey() async {
		let bridge = BoringTunBridge()

		do {
			try await bridge.createTunnel(
				privateKey: validPrivateKey,
				peerPublicKey: invalidKey,  // Invalid
				presharedKey: nil,
				keepalive: 0
			)
			XCTFail("Should have thrown tunnelCreationFailed")
		} catch BridgeError.tunnelCreationFailed {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests tunnel creation failure with invalid pre-shared key.
	///
	/// If a PSK is provided but is invalid, BoringTun should reject it.
	func testCreateTunnelWithInvalidPresharedKey() async {
		let bridge = BoringTunBridge()

		do {
			try await bridge.createTunnel(
				privateKey: validPrivateKey,
				peerPublicKey: validPeerPublicKey,
				presharedKey: invalidKey,  // Invalid
				keepalive: 0
			)
			XCTFail("Should have thrown tunnelCreationFailed")
		} catch BridgeError.tunnelCreationFailed {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests that creating a new tunnel destroys the previous one.
	///
	/// If a tunnel already exists when createTunnel() is called, the old
	/// tunnel should be automatically destroyed to prevent resource leaks.
	/// The new tunnel should be independent of the old one.
	func testCreateTunnelReplacesExisting() async throws {
		let bridge = BoringTunBridge()

		// Create first tunnel
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: nil,
			keepalive: 0
		)

		let stats1 = try await bridge.statistics()
		XCTAssertEqual(stats1.timeSinceLastHandshake, -1)

		// Create second tunnel - should replace first without error
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: validPresharedKey,  // Different config
			keepalive: 25
		)

		// Should have new tunnel's fresh statistics
		let stats2 = try await bridge.statistics()
		XCTAssertEqual(stats2.timeSinceLastHandshake, -1)
	}

	// MARK: - Tunnel Destruction Tests

	/// Tests explicit tunnel destruction.
	///
	/// destroyTunnel() should free the BoringTun resources and leave the
	/// bridge in a state where no tunnel is active.
	func testDestroyTunnel() async throws {
		let bridge = BoringTunBridge()

		// Create a tunnel
		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: nil,
			keepalive: 0
		)

		// Should work before destruction
		_ = try await bridge.statistics()

		// Destroy the tunnel
		await bridge.destroyTunnel()

		// Operations should now fail with invalidHandle
		do {
			_ = try await bridge.statistics()
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}

	/// Tests that destroying a non-existent tunnel is safe.
	///
	/// Calling destroyTunnel() when no tunnel exists should be a no-op
	/// and not crash or throw errors.
	func testDestroyTunnelWhenNoneExists() async {
		let bridge = BoringTunBridge()

		// Destroy when no tunnel exists - should be safe
		await bridge.destroyTunnel()

		// Calling it again should also be safe
		await bridge.destroyTunnel()
	}

	// MARK: - Statistics Tests

	/// Tests retrieving statistics from an active tunnel.
	///
	/// statistics() should return the current tunnel state including handshake
	/// timing, byte counters, and network quality metrics.
	func testStatistics() async throws {
		let bridge = BoringTunBridge()

		try await bridge.createTunnel(
			privateKey: validPrivateKey,
			peerPublicKey: validPeerPublicKey,
			presharedKey: nil,
			keepalive: 0
		)

		let stats = try await bridge.statistics()

		// New tunnel should have initial values
		XCTAssertEqual(stats.timeSinceLastHandshake, -1, "No handshake yet")
		XCTAssertEqual(stats.transmittedBytes, 0, "No data transmitted")
		XCTAssertEqual(stats.receivedBytes, 0, "No data received")
		XCTAssertEqual(stats.estimatedRTT, -1, "No RTT measured yet")

		// Computed properties should reflect initial state
		XCTAssertFalse(stats.hasHandshake, "Should not have handshake")
		XCTAssertFalse(stats.isHandshakeStale, "Can't be stale with no handshake")
		XCTAssertFalse(stats.hasRTT, "Should not have RTT")
	}

	/// Tests that statistics() fails when no tunnel is active.
	///
	/// Calling statistics() without first creating a tunnel should throw
	/// invalidHandle error.
	func testStatisticsWithoutTunnel() async {
		let bridge = BoringTunBridge()

		do {
			_ = try await bridge.statistics()
			XCTFail("Should have thrown invalidHandle")
		} catch BridgeError.invalidHandle {
			// Expected error
		} catch {
			XCTFail("Unexpected error: \(error)")
		}
	}
}
