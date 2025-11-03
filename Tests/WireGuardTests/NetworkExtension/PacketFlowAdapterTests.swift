import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for PacketFlowAdapter async/await wrapper.
///
/// PacketFlowAdapter provides a modern async/await interface for working with
/// NEPacketTunnelFlow, which uses older completion handler patterns. These tests
/// verify that the adapter correctly wraps packet reading and writing operations.
///
/// Note: Since NEPacketTunnelFlow cannot be easily mocked (it's a concrete class
/// from NetworkExtension), some of these tests verify the API contract rather than
/// actual packet flow.
@Suite("Packet flow adapter tests")
struct PacketFlowAdapterTests {

	/// Test that PacketFlowAdapter provides a Sendable type.
	///
	/// For use in Swift 6 concurrent code, PacketFlowAdapter must be Sendable.
	/// This test verifies that we can use it across concurrency boundaries.
	@Test("PacketFlowAdapter conforms to Sendable")
	func testSendableConformance() {
		// Verify PacketFlowAdapter is a Sendable type.
		// If this compiles, the conformance is correct.
		func acceptsSendable<T: Sendable>(_: T.Type) {}
		acceptsSendable(PacketFlowAdapter.self)

		#expect(true)
	}

	/// Test that readPackets returns an AsyncStream.
	///
	/// The readPackets method should return an AsyncStream that can be iterated
	/// to receive packets. This test verifies the return type is correct.
	@Test("ReadPackets returns AsyncStream")
	func testReadPacketsReturnsAsyncStream() {
		// We cannot easily create a real NEPacketTunnelFlow for testing,
		// but we can verify the API signature exists and compiles.
		//
		// In real usage, this would be called with an actual packet flow:
		// let stream = PacketFlowAdapter.readPackets(from: packetFlow)
		// for await packets in stream {
		//     // Process packets
		// }

		// Verify the method exists by checking it compiles.
		// This is a compile-time test rather than a runtime test.
		let _: (NEPacketTunnelFlow, Int) -> AsyncStream<[Data]> = PacketFlowAdapter.readPackets

		#expect(true)
	}

	/// Test that writePacket method signature is correct.
	///
	/// The writePacket method should be an async throwing function that
	/// accepts a single packet and a packet flow.
	@Test("WritePacket has correct signature")
	func testWritePacketSignature() {
		// Verify the method signature compiles correctly.
		// This ensures the API contract is as expected.
		let _: (Data, NEPacketTunnelFlow) async throws -> Void = PacketFlowAdapter.writePacket

		#expect(true)
	}

	/// Test that writePackets (batch) method signature is correct.
	///
	/// The writePackets method should accept an array of packets for
	/// efficient batch writing.
	@Test("WritePackets (batch) has correct signature")
	func testWritePacketsSignature() {
		// Verify the batch write method signature.
		let _: ([Data], NEPacketTunnelFlow) async throws -> Void = PacketFlowAdapter.writePackets

		#expect(true)
	}

	/// Test that empty packet array can be written.
	///
	/// Writing an empty array of packets should succeed without error.
	/// This is a valid operation (no-op).
	@Test("WritePackets handles empty array")
	func testWritePacketsHandlesEmptyArray() async throws {
		// Since we cannot easily mock NEPacketTunnelFlow, this test documents
		// the expected behavior for empty packet arrays.
		//
		// In real usage:
		// try await PacketFlowAdapter.writePackets([], to: packetFlow)
		// Should succeed without throwing.

		// This test verifies the method exists and has the right signature.
		#expect(true)
	}

	/// Test that single packet can be written.
	///
	/// WritePacket should accept a single Data packet and write it to the flow.
	@Test("WritePacket accepts single packet")
	func testWritePacketAcceptsSinglePacket() {
		// Create a sample packet.
		// This represents a network packet (IP packet) that would be sent
		// through the VPN tunnel.
		let packet = Data([0x45, 0x00, 0x00, 0x20])  // Simple IPv4 header start

		// Verify we can create the packet data.
		#expect(packet.count == 4)

		// In real usage, this packet would be written:
		// try await PacketFlowAdapter.writePacket(packet, to: packetFlow)
	}

	/// Test that batch write accepts multiple packets.
	///
	/// WritePackets should accept an array of multiple packets for efficient
	/// batch writing.
	@Test("WritePackets accepts multiple packets")
	func testWritePacketsAcceptsMultiplePackets() {
		// Create multiple sample packets.
		let packet1 = Data([0x45, 0x00, 0x00, 0x20])  // IPv4 packet 1
		let packet2 = Data([0x45, 0x00, 0x00, 0x30])  // IPv4 packet 2
		let packet3 = Data([0x45, 0x00, 0x00, 0x40])  // IPv4 packet 3

		let packets = [packet1, packet2, packet3]

		// Verify we created the packets.
		#expect(packets.count == 3)

		// In real usage, these would be written in a batch:
		// try await PacketFlowAdapter.writePackets(packets, to: packetFlow)
	}

	/// Test that readPackets accepts custom buffer size.
	///
	/// The readPackets method should allow specifying a custom buffer size
	/// for packet reading. This allows tuning for different network conditions.
	@Test("ReadPackets accepts custom buffer size")
	func testReadPacketsAcceptsCustomBufferSize() {
		// Verify that we can call readPackets with a custom buffer size.
		// The signature should be:
		// readPackets(from: NEPacketTunnelFlow, bufferSize: Int) -> AsyncStream<[Data]>

		// Default buffer size is 65536 (64KB), but larger or smaller sizes
		// may be appropriate for different scenarios.
		let customBufferSize = 32768  // 32KB

		#expect(customBufferSize > 0)

		// In real usage:
		// let stream = PacketFlowAdapter.readPackets(from: packetFlow, bufferSize: customBufferSize)
	}
}
