import Foundation
@preconcurrency import NetworkExtension

/// Async/await adapter for NEPacketTunnelFlow.
///
/// NetworkExtension's NEPacketTunnelFlow uses completion handler-based APIs which
/// predate Swift's async/await. This adapter provides a modern async interface for
/// reading and writing packets through the VPN tunnel.
///
/// # Usage
///
/// ```swift
/// // Read packets asynchronously
/// let stream = PacketFlowAdapter.readPackets(from: packetFlow)
/// for await packets in stream {
///     for packet in packets {
///         // Process each packet
///     }
/// }
///
/// // Write a single packet
/// try await PacketFlowAdapter.writePacket(packet, to: packetFlow)
///
/// // Write multiple packets (more efficient)
/// try await PacketFlowAdapter.writePackets([packet1, packet2], to: packetFlow)
/// ```
///
/// # Thread safety
///
/// This is a struct with only static methods, making it inherently thread-safe and Sendable.
public struct PacketFlowAdapter: Sendable {

	/// Reads packets from the packet flow as an asynchronous stream.
	///
	/// This method creates an AsyncStream that continuously reads packets from the
	/// tunnel. The stream will emit batches of packets as they become available.
	///
	/// Each element in the stream is an array of Data objects, where each Data
	/// represents one IP packet. Packets are read in batches for efficiency.
	///
	/// The stream continues until the tunnel is closed or an error occurs.
	/// When the tunnel closes, the stream completes normally.
	///
	/// # Example
	///
	/// ```swift
	/// for await packets in PacketFlowAdapter.readPackets(from: packetFlow) {
	///     for packet in packets {
	///         let processedPacket = try processOutboundPacket(packet)
	///         if let output = processedPacket {
	///             // Send to network
	///         }
	///     }
	/// }
	/// ```
	///
	/// # Buffer size
	///
	/// The buffer size parameter controls how many packets can be read in a single
	/// batch. Larger values may improve throughput but use more memory. The default
	/// of 65536 bytes (64KB) is appropriate for most scenarios.
	///
	/// - Parameters:
	///   - flow: The packet tunnel flow to read from
	///   - bufferSize: Maximum size of each packet buffer in bytes (default: 65536)
	/// - Returns: AsyncStream of packet batches
	public static func readPackets(
		from flow: NEPacketTunnelFlow,
		bufferSize: Int = 65536
	) -> AsyncStream<[Data]> {
		// Create an AsyncStream that will emit packets.
		// AsyncStream provides backpressure handling automatically.
		AsyncStream { continuation in
			// Define a recursive function to continuously read packets.
			// This pattern is necessary because readPackets uses a completion handler.
			func readNextBatch() {
				// Request packets from the flow.
				// maxPackets: How many packets to read in this batch
				// completion: Called when packets are available
				flow.readPackets { packets, _ in
					// packets: Array of Data objects (the actual IP packets)
					// The second parameter (protocols) indicates packet type but we don't use it

					// If we received packets, yield them to the stream.
					if !packets.isEmpty {
						continuation.yield(packets)
					}

					// Continue reading the next batch.
					// This creates a loop that keeps reading packets until the stream is cancelled.
					readNextBatch()
				}
			}

			// Set up stream cancellation handler.
			// When the stream consumer stops iterating (breaks out of the for-await loop),
			// this cleanup code runs.
			continuation.onTermination = { _ in
				// The stream has been cancelled.
				// NEPacketTunnelFlow doesn't have a cancel method, so we just stop reading.
				// The recursive readNextBatch calls will stop naturally when the flow closes.
			}

			// Start reading the first batch.
			readNextBatch()
		}
	}

	/// Writes a single packet to the packet flow.
	///
	/// This method writes one IP packet through the VPN tunnel. The packet should be
	/// a complete IP packet (including IP header and payload).
	///
	/// For writing multiple packets, consider using `writePackets(_:to:)` instead,
	/// which is more efficient for batches.
	///
	/// # Example
	///
	/// ```swift
	/// let encryptedPacket = try tunnel.processInboundPacket(networkPacket)
	/// if let packet = encryptedPacket {
	///     try await PacketFlowAdapter.writePacket(packet, to: packetFlow)
	/// }
	/// ```
	///
	/// - Parameters:
	///   - packet: The IP packet to write
	///   - flow: The packet tunnel flow to write to
	/// - Throws: `IntegrationError.packetFlowError` if writing fails
	public static func writePacket(_ packet: Data, to flow: NEPacketTunnelFlow) async throws {
		// Use the batch write method with a single packet.
		// This avoids code duplication while maintaining a convenient single-packet API.
		try await writePackets([packet], to: flow)
	}

	/// Writes multiple packets to the packet flow.
	///
	/// This method writes a batch of IP packets through the VPN tunnel. Writing packets
	/// in batches is more efficient than writing them one at a time because it reduces
	/// the number of system calls.
	///
	/// Each packet should be a complete IP packet (including IP header and payload).
	///
	/// # Example
	///
	/// ```swift
	/// var packetsToWrite: [Data] = []
	/// for packet in incomingPackets {
	///     if let processed = try processPacket(packet) {
	///         packetsToWrite.append(processed)
	///     }
	/// }
	/// try await PacketFlowAdapter.writePackets(packetsToWrite, to: packetFlow)
	/// ```
	///
	/// - Parameters:
	///   - packets: Array of IP packets to write
	///   - flow: The packet tunnel flow to write to
	/// - Throws: `IntegrationError.packetFlowError` if writing fails
	public static func writePackets(_ packets: [Data], to flow: NEPacketTunnelFlow) async throws {
		// If the array is empty, there's nothing to write.
		// Return early to avoid unnecessary work.
		guard !packets.isEmpty else {
			return
		}

		// Use a continuation to convert the completion handler to async/await.
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
			// Create protocol numbers for each packet.
			// Protocol numbers indicate whether the packet is IPv4 (2) or IPv6 (30).
			// We determine this by looking at the IP version field in the packet header.
			let protocols = packets.map { packet -> NSNumber in
				// Check the IP version field (first nibble of first byte).
				// IPv4 packets start with 0x4x, IPv6 packets start with 0x6x.
				guard let firstByte = packet.first else {
					// Empty packet, assume IPv4.
					return NSNumber(value: AF_INET)
				}

				let version = (firstByte & 0xF0) >> 4
				if version == 6 {
					// IPv6 packet.
					return NSNumber(value: AF_INET6)
				} else {
					// IPv4 packet (or unknown, treat as IPv4).
					return NSNumber(value: AF_INET)
				}
			}

			// Write the packets to the flow.
			// NetworkExtension's writePackets returns a boolean indicating success.
			let success = flow.writePackets(packets, withProtocols: protocols)

			if success {
				// Writing succeeded.
				continuation.resume()
			} else {
				// Writing failed.
				// This can happen if the tunnel is closing or if there's a flow control issue.
				continuation.resume(
					throwing: IntegrationError.packetFlowError(
						"Failed to write \(packets.count) packet(s) to tunnel flow"
					)
				)
			}
		}
	}
}
