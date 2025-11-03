// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for packet processor lifecycle operations and resource management.
///
/// These tests verify that periodic maintenance (tick), handshake initiation,
/// statistics retrieval, buffer reuse, and concurrent access all work correctly.
struct PacketProcessorLifecycleTests {
	// MARK: - Tick operation tests

	/// Verifies that tick operation succeeds.
	///
	/// The tick operation performs periodic maintenance like keepalives and
	/// timeout checks. It should complete without error even if it doesn't
	/// produce a packet to send.
	@Test("Tick operation succeeds")
	func tickOperationSucceeds() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Perform tick operation
		let result = try await processor.tick()

		// Result may be nil (no packet needed) or contain data (keepalive/handshake)
		// Both are valid outcomes
		if let packet = result {
			#expect(packet.count > 0)
		}
	}

	/// Verifies that tick can be called multiple times.
	///
	/// The tick operation should be safely repeatable, allowing it to be
	/// called in a periodic loop without issues.
	@Test("Tick can be called multiple times")
	func tickCanBeCalledMultipleTimes() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Call tick multiple times
		for _ in 0..<5 {
			let result = try await processor.tick()
			// Each call should succeed (return nil or a packet)
			if let packet = result {
				#expect(packet.count > 0)
			}
		}
	}

	// MARK: - Force handshake tests

	/// Verifies that force handshake produces a packet.
	///
	/// Forcing a handshake should always produce a handshake initiation packet
	/// that can be sent to the peer to establish or refresh the session.
	@Test("Force handshake produces packet")
	func forceHandshakeProducesPacket() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Force a handshake
		let handshakePacket = try await processor.forceHandshake()

		// Verify we got a packet
		#expect(handshakePacket.count > 0)

		// Verify it looks like a handshake initiation (type 1)
		#expect(handshakePacket.first == 0x01)
	}

	/// Verifies that force handshake can be called multiple times.
	///
	/// The handshake operation should be repeatable, allowing manual rekeys
	/// or recovery from connection issues.
	@Test("Force handshake can be called multiple times")
	func forceHandshakeCanBeCalledMultipleTimes() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Force handshakes multiple times
		for _ in 0..<3 {
			let handshakePacket = try await processor.forceHandshake()
			#expect(handshakePacket.count > 0)
			#expect(handshakePacket.first == 0x01)
		}
	}

	// MARK: - Statistics tests

	/// Verifies that statistics can be retrieved.
	///
	/// The processor should be able to query the bridge for current tunnel
	/// statistics at any time.
	@Test("Statistics can be retrieved")
	func statisticsCanBeRetrieved() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Get statistics
		let stats = try await processor.statistics()

		// Verify we got valid statistics (initial values)
		#expect(stats.transmittedBytes == 0)
		#expect(stats.receivedBytes == 0)
		#expect(stats.hasHandshake == false)
	}

	/// Verifies that statistics can be retrieved multiple times.
	///
	/// Statistics queries should be repeatable and reflect the current state
	/// of the tunnel each time they're called.
	@Test("Statistics can be retrieved multiple times")
	func statisticsCanBeRetrievedMultipleTimes() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Get statistics multiple times
		for _ in 0..<3 {
			let stats = try await processor.statistics()
			#expect(stats.transmittedBytes == 0)
			#expect(stats.receivedBytes == 0)
		}
	}

	// MARK: - Buffer reuse tests

	/// Verifies that processing multiple packets works correctly.
	///
	/// This tests that the internal packet buffer is properly reused across
	/// multiple operations without corruption or interference between packets.
	@Test("Multiple packets can be processed sequentially")
	func multiplePacketsCanBeProcessedSequentially() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Process multiple different packets
		let packets = [
			Data([
				0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			]),
			Data([
				0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			]),
			Data([
				0x45, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			])
		]

		// Each packet should be processed independently
		for packet in packets {
			let result = try await processor.processOutbound(packet)
			// Result may be nil or data, both are valid
			if let encrypted = result {
				#expect(encrypted.count > 0)
			}
		}
	}

	// MARK: - Concurrent access tests

	/// Verifies that processor operations are properly serialized.
	///
	/// Since PacketProcessor is an actor, concurrent calls should be automatically
	/// serialized to prevent data races in the packet buffer. This test verifies
	/// that multiple concurrent operations complete successfully.
	@Test("Concurrent operations are properly serialized")
	func concurrentOperationsAreProperlySerializer() async throws {
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		let processor = PacketProcessor(bridge: bridge)

		// Launch multiple concurrent operations
		async let stats1 = processor.statistics()
		async let stats2 = processor.statistics()
		async let tick1 = processor.tick()
		async let tick2 = processor.tick()

		// All operations should complete successfully
		_ = try await stats1
		_ = try await stats2
		_ = try await tick1
		_ = try await tick2

		// If we get here, all operations completed without crashes or data races
	}
}
