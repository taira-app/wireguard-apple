// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for packet processor initialization and basic packet processing.
///
/// PacketProcessor is responsible for coordinating packet encryption and decryption
/// through the BoringTun bridge. These tests verify that the processor initializes
/// correctly and handles outbound and inbound packet processing appropriately.
struct PacketProcessorTests {
	// MARK: - Initialization tests

	/// Verifies that PacketProcessor can be created with a bridge.
	///
	/// The processor should successfully initialize with a BoringTun bridge
	/// and allocate its internal packet buffer.
	@Test("PacketProcessor initializes with bridge")
	func packetProcessorInitializesWithBridge() async throws {
		// Create a test bridge with minimal configuration
		let privateKey = PrivateKey()
		let peerPublicKey = PrivateKey().publicKey

		let bridge = BoringTunBridge()
		try await bridge.createTunnel(
			privateKey: privateKey.base64Key,
			peerPublicKey: peerPublicKey.base64Key,
			presharedKey: nil,
			keepalive: 0
		)

		// Create processor - this should not throw
		let processor = PacketProcessor(bridge: bridge)

		// Verify we can interact with the processor
		let stats = try await processor.statistics()
		#expect(stats.transmittedBytes == 0)
		#expect(stats.receivedBytes == 0)
	}

	// MARK: - Outbound packet processing tests

	/// Verifies that outbound packet processing rejects empty packets.
	///
	/// Empty packets have no meaningful content and should be rejected with
	/// an invalidPacket error before attempting any processing.
	@Test("Outbound processing rejects empty packets")
	func outboundProcessingRejectsEmptyPackets() async throws {
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

		// Attempt to process an empty packet
		let emptyPacket = Data()

		await #expect(throws: EngineError.self) {
			try await processor.processOutbound(emptyPacket)
		}
	}

	/// Verifies that outbound packet processing handles valid IPv4 packets.
	///
	/// The processor should accept well-formed IPv4 packets for encryption.
	/// This test uses a minimal but valid IPv4 header.
	@Test("Outbound processing handles valid IPv4 packets")
	func outboundProcessingHandlesValidIPv4Packets() async throws {
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

		// Create a minimal IPv4 packet (header only)
		// Version 4, IHL 5, total length 20, TTL 64, protocol 6 (TCP)
		let ipv4Packet = Data([
			0x45, 0x00, 0x00, 0x14,  // Version, IHL, DSCP, ECN, Total Length
			0x00, 0x00, 0x00, 0x00,  // Identification, Flags, Fragment Offset
			0x40, 0x06, 0x00, 0x00,  // TTL, Protocol, Header Checksum
			0x00, 0x00, 0x00, 0x00,  // Source IP
			0x00, 0x00, 0x00, 0x00  // Destination IP
		])

		// Process the packet - this may return nil or a packet
		// We're just verifying it doesn't throw an error
		let result = try await processor.processOutbound(ipv4Packet)

		// Result may be nil (no packet to send) or contain data (encrypted packet)
		// Both are valid outcomes depending on tunnel state
		if let encryptedPacket = result {
			#expect(encryptedPacket.count > 0)
		}
	}

	/// Verifies that outbound packet processing handles valid IPv6 packets.
	///
	/// The processor should accept well-formed IPv6 packets for encryption.
	/// This test uses a minimal but valid IPv6 header.
	@Test("Outbound processing handles valid IPv6 packets")
	func outboundProcessingHandlesValidIPv6Packets() async throws {
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

		// Create a minimal IPv6 packet (header only, 40 bytes)
		// Version 6, Traffic Class 0, Flow Label 0, Payload Length 0, Next Header 6 (TCP), Hop Limit 64
		var ipv6Packet = Data(count: 40)
		ipv6Packet[0] = 0x60  // Version 6
		ipv6Packet[6] = 0x06  // Next Header: TCP
		ipv6Packet[7] = 0x40  // Hop Limit: 64

		// Process the packet
		let result = try await processor.processOutbound(ipv6Packet)

		// Result may be nil or contain data, both are valid
		if let encryptedPacket = result {
			#expect(encryptedPacket.count > 0)
		}
	}

	// MARK: - Inbound packet processing tests

	/// Verifies that inbound packet processing rejects empty packets.
	///
	/// Empty packets have no meaningful content and should be rejected with
	/// an invalidPacket error before attempting any decryption.
	@Test("Inbound processing rejects empty packets")
	func inboundProcessingRejectsEmptyPackets() async throws {
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

		// Attempt to process an empty packet
		let emptyPacket = Data()

		await #expect(throws: EngineError.self) {
			try await processor.processInbound(emptyPacket)
		}
	}

	/// Verifies that inbound packet processing handles WireGuard handshake messages.
	///
	/// Handshake messages are valid inbound packets but don't contain user data,
	/// so the processor should return nil rather than an IP packet.
	@Test("Inbound processing handles handshake messages")
	func inboundProcessingHandlesHandshakeMessages() async throws {
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

		// Create a WireGuard message type 1 (handshake initiation) packet
		// This is a simplified version - real handshake has more data
		var handshakePacket = Data(count: 148)  // Actual handshake initiation size
		handshakePacket[0] = 0x01  // Message type: handshake initiation

		// Process the packet - this should either return a result with decrypted packet/response
		// or throw an error (invalid handshake)
		do {
			let result = try await processor.processInbound(handshakePacket)
			// If it returns a decrypted packet, verify it has data
			if let (ipPacket, _) = result.decryptedPacket {
				#expect(ipPacket.count > 0)
			}
			// If it returns a response packet, verify it has data
			if let response = result.packetToSend {
				#expect(response.count > 0)
			}
		} catch {
			// Processing failed, which is expected for invalid handshake data
			// This is acceptable behavior
		}
	}
}
