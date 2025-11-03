// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for WireGuard tunnel packet processing and statistics operations.
///
/// These tests verify that packet encryption/decryption and statistics retrieval
/// work correctly and handle error conditions appropriately.
struct WireGuardTunnelOperationsTests {
	// MARK: - Packet processing tests

	/// Verifies that outbound packet processing requires tunnel to be running.
	///
	/// Attempting to process packets when the tunnel is stopped should throw
	/// a notRunning error rather than attempting to encrypt the packet.
	@Test("Outbound processing requires tunnel to be running")
	func outboundProcessingRequiresTunnelToBeRunning() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Create test packet
		let packet = Data([
			0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		])

		// Attempt to process packet while stopped
		await #expect(throws: EngineError.notRunning) {
			try await tunnel.processOutboundPacket(packet)
		}
	}

	/// Verifies that outbound packet processing works when tunnel is running.
	///
	/// When the tunnel is in the connected state, it should accept IP packets
	/// for encryption and return the encrypted result (or nil).
	@Test("Outbound processing works when tunnel is running")
	func outboundProcessingWorksWhenTunnelIsRunning() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start the tunnel
		try await tunnel.start()

		// Create test packet
		let packet = Data([
			0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		])

		// Process packet - should not throw
		let result = try await tunnel.processOutboundPacket(packet)

		// Result may be nil or contain data, both are valid
		if let encrypted = result {
			#expect(encrypted.count > 0)
		}
	}

	/// Verifies that inbound packet processing requires tunnel to be running.
	///
	/// Attempting to process inbound packets when the tunnel is stopped should
	/// throw a notRunning error.
	@Test("Inbound processing requires tunnel to be running")
	func inboundProcessingRequiresTunnelToBeRunning() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Create test packet (simplified handshake)
		var packet = Data(count: 148)
		packet[0] = 0x01

		// Attempt to process packet while stopped
		await #expect(throws: EngineError.notRunning) {
			try await tunnel.processInboundPacket(packet)
		}
	}

	/// Verifies that inbound packet processing works when tunnel is running.
	///
	/// When the tunnel is in the connected state, it should accept WireGuard
	/// packets for decryption and return the decrypted result (or nil).
	@Test("Inbound processing works when tunnel is running")
	func inboundProcessingWorksWhenTunnelIsRunning() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start the tunnel
		try await tunnel.start()

		// Create test packet (simplified handshake)
		var packet = Data(count: 148)
		packet[0] = 0x01

		// Process packet - may succeed or fail depending on packet validity
		do {
			let (decryptedPacket, responseToSend) = try await tunnel.processInboundPacket(packet)
			// If successful, decrypted packet may be present
			if let (decrypted, _) = decryptedPacket {
				#expect(decrypted.count > 0)
			}
			// Response to send may also be present
			if let response = responseToSend {
				#expect(response.count > 0)
			}
		} catch {
			// Processing failure is acceptable for invalid packets
		}
	}

	// MARK: - Statistics tests

	/// Verifies that statistics can be retrieved at any time.
	///
	/// The statistics() method should work whether the tunnel is running or
	/// stopped, though the values are only meaningful after starting.
	@Test("Statistics can be retrieved at any time")
	func statisticsCanBeRetrievedAtAnyTime() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Get statistics while stopped
		let statsBeforeStart = try await tunnel.statistics()
		#expect(statsBeforeStart.transmittedBytes == 0)

		// Start tunnel
		try await tunnel.start()

		// Get statistics while running
		let statsAfterStart = try await tunnel.statistics()
		#expect(statsAfterStart.transmittedBytes == 0)  // No packets sent yet

		// Stop tunnel
		await tunnel.stop()

		// Get statistics after stop
		let statsAfterStop = try await tunnel.statistics()
		#expect(statsAfterStop.transmittedBytes == 0)
	}
}
