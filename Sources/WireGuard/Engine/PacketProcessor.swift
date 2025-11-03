// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation

/// Result of processing an inbound packet.
///
/// When processing inbound packets from the network, BoringTun may produce two types
/// of output that require different handling:
///
/// - **Decrypted packet**: A successfully decrypted IP packet that should be injected
///   into the tunnel interface for the operating system to route.
/// - **Response packet**: A WireGuard protocol message (such as a handshake response)
///   that must be sent back to the peer via UDP.
///
/// Both types may be present simultaneously, for example when receiving a handshake
/// initiation that also contains data.
public struct InboundProcessingResult: Sendable {
	/// Decrypted IP packet to inject into the tunnel interface, if any.
	///
	/// This will be present when the inbound packet was a WireGuard data packet
	/// containing encrypted IP traffic. The boolean indicates whether it's IPv4
	/// (true) or IPv6 (false), which helps with routing.
	public let decryptedPacket: (Data, isIPv4: Bool)?

	/// Packet to send back to the peer, if any.
	///
	/// This will be present when BoringTun generates a protocol message that needs
	/// to be transmitted, such as:
	/// - Handshake response (in response to handshake initiation)
	/// - Handshake initiation (in response to handshake response)
	/// - Cookie reply (for under-load protection)
	public let packetToSend: Data?
}

/// Actor responsible for processing packets through the BoringTun bridge.
///
/// PacketProcessor coordinates the encryption and decryption of packets using
/// the BoringTun FFI layer. It maintains packet buffers and handles the
/// low-level details of packet processing while providing a clean async API.
///
/// ## Responsibilities
///
/// - **Outbound processing**: Encrypts IP packets for transmission over the network
/// - **Inbound processing**: Decrypts network packets into IP packets for the system
/// - **Periodic maintenance**: Performs tick operations for keepalives and timeouts
/// - **Handshake initiation**: Forces handshake when needed
/// - **Buffer management**: Reuses buffers to minimize allocations
///
/// ## Example usage
///
/// ```swift
/// let bridge = try await BoringTunBridge()
/// let processor = PacketProcessor(bridge: bridge)
///
/// // Process outbound IP packet (encrypt for network)
/// let ipPacket = Data([0x45, 0x00, ...])  // IPv4 packet
/// if let encryptedPacket = try await processor.processOutbound(ipPacket) {
///     // Send encryptedPacket over network to peer
/// }
///
/// // Process inbound network packet (decrypt to IP packet)
/// let networkPacket = Data([0x04, ...])  // WireGuard packet
/// let result = try await processor.processInbound(networkPacket)
/// if let (ipPacket, _) = result.decryptedPacket {
///     // Inject ipPacket into system network stack
/// }
/// if let response = result.packetToSend {
///     // Send response back to peer via UDP
/// }
///
/// // Periodic maintenance
/// try await processor.tick()
/// ```
actor PacketProcessor {
	/// The BoringTun bridge used for packet processing.
	///
	/// All packet encryption, decryption, and handshake operations are
	/// delegated to this bridge, which wraps the Rust BoringTun implementation.
	private let bridge: BoringTunBridge

	/// Maximum packet size for WireGuard.
	///
	/// WireGuard packets never exceed 1500 bytes (standard MTU), but we allocate
	/// a slightly larger buffer to handle potential overhead and future-proofing.
	/// This matches the buffer size used in BoringTun itself.
	private static let maximumPacketSize = 2048

	/// Reusable buffer for packet processing.
	///
	/// This buffer is reused across packet processing operations to minimize
	/// memory allocations. It's large enough to handle any valid WireGuard
	/// packet plus overhead.
	///
	/// Marked `nonisolated(unsafe)` to allow passing as `inout` parameter to
	/// bridge methods. This is safe because PacketProcessor is an actor and all
	/// access to the buffer is serialized through actor isolation.
	nonisolated(unsafe) private var packetBuffer: [UInt8]

	/// Creates a new packet processor.
	///
	/// The processor allocates a reusable packet buffer and stores a reference
	/// to the BoringTun bridge for performing cryptographic operations.
	///
	/// - Parameter bridge: The BoringTun bridge to use for packet processing
	init(bridge: BoringTunBridge) {
		self.bridge = bridge
		self.packetBuffer = [UInt8](repeating: 0, count: Self.maximumPacketSize)
	}

	/// Processes an outbound IP packet for transmission over the network.
	///
	/// This method takes an IP packet (either IPv4 or IPv6) from the system's
	/// network stack and encrypts it into a WireGuard packet suitable for
	/// transmission to the peer.
	///
	/// The method may return nil if the packet should not be sent (for example,
	/// if the handshake is not yet complete and the packet is queued).
	///
	/// - Parameter packet: The IP packet to encrypt
	/// - Returns: The encrypted WireGuard packet, or nil if no packet should be sent
	/// - Throws: EngineError.invalidPacket if the packet is malformed
	/// - Throws: EngineError.processingFailed if encryption fails
	func processOutbound(_ packet: Data) async throws -> Data? {
		guard !packet.isEmpty else {
			throw EngineError.invalidPacket(packet)
		}

		// Process through bridge
		do {
			let result = try await bridge.processOutboundPacket(packet, into: &packetBuffer)

			// Convert result to Data if we got a packet to send
			guard result.size > 0 else {
				return nil
			}

			return Data(packetBuffer.prefix(result.size))
		} catch {
			throw EngineError.processingFailed(error)
		}
	}

	/// Processes an inbound network packet from the peer.
	///
	/// This method takes an encrypted WireGuard packet received from the network
	/// and processes it, potentially producing two types of output:
	///
	/// 1. A decrypted IP packet to inject into the tunnel interface
	/// 2. A response packet to send back to the peer (e.g., handshake response)
	///
	/// The caller is responsible for handling both types of output. Failing to send
	/// response packets will cause handshakes to fail and the tunnel to not connect.
	///
	/// - Parameter packet: The encrypted WireGuard packet from the network
	/// - Returns: An InboundProcessingResult containing any decrypted packet and/or response
	/// - Throws: EngineError.invalidPacket if the packet is malformed
	/// - Throws: EngineError.processingFailed if decryption fails
	func processInbound(_ packet: Data) async throws -> InboundProcessingResult {
		guard !packet.isEmpty else {
			throw EngineError.invalidPacket(packet)
		}

		// Process through bridge
		do {
			let result = try await bridge.processInboundPacket(packet, into: &packetBuffer)

			// Handle different operation types
			var decryptedPacket: (Data, isIPv4: Bool)?
			var packetToSend: Data?

			if result.size > 0 {
				switch result.operation {
				case .writeToTunnelIPv4:
					// Got a decrypted IPv4 packet
					decryptedPacket = (Data(packetBuffer.prefix(result.size)), isIPv4: true)

				case .writeToTunnelIPv6:
					// Got a decrypted IPv6 packet
					decryptedPacket = (Data(packetBuffer.prefix(result.size)), isIPv4: false)

				case .writeToNetwork:
					// Got a packet that needs to be sent to the peer (handshake response, etc.)
					packetToSend = Data(packetBuffer.prefix(result.size))

				case .done:
					// Packet was processed but no output (e.g., keepalive received)
					break

				case .error:
					// Should not happen as bridge would have thrown
					throw EngineError.processingFailed(
						BridgeError.operationFailed("Unexpected error result"))
				}
			}

			return InboundProcessingResult(
				decryptedPacket: decryptedPacket,
				packetToSend: packetToSend
			)
		} catch {
			throw EngineError.processingFailed(error)
		}
	}

	/// Performs periodic tunnel maintenance.
	///
	/// This method should be called regularly (recommended every 10-100ms) to
	/// allow BoringTun to perform necessary maintenance tasks:
	///
	/// - Sending keepalive packets if configured
	/// - Checking for handshake timeouts
	/// - Expiring old sessions
	/// - Initiating rekeys when needed
	///
	/// The method may return a packet that should be sent to the peer (such as
	/// a keepalive or handshake initiation).
	///
	/// - Returns: A packet to send to the peer, or nil if no packet is needed
	/// - Throws: EngineError.processingFailed if the tick operation fails
	func tick() async throws -> Data? {
		do {
			let result = try await bridge.tick(into: &packetBuffer)

			guard result.size > 0 else {
				return nil
			}

			return Data(packetBuffer.prefix(result.size))
		} catch {
			throw EngineError.processingFailed(error)
		}
	}

	/// Forces a handshake initiation with the peer.
	///
	/// This method explicitly requests a new handshake, which is useful when:
	/// - The connection appears to be stale
	/// - Network conditions have changed
	/// - Manual rekey is desired for forward secrecy
	///
	/// The method returns a handshake initiation packet that should be sent
	/// to the peer.
	///
	/// - Returns: A handshake initiation packet to send to the peer
	/// - Throws: EngineError.handshakeFailed if handshake initiation fails
	func forceHandshake() async throws -> Data {
		do {
			let result = try await bridge.forceHandshake(into: &packetBuffer)

			guard result.size > 0 else {
				throw EngineError.handshakeFailed("Handshake initiation produced no packet")
			}

			return Data(packetBuffer.prefix(result.size))
		} catch {
			if let engineError = error as? EngineError {
				throw engineError
			}
			throw EngineError.handshakeFailed("Bridge error: \(error.localizedDescription)")
		}
	}

	/// Retrieves current tunnel statistics.
	///
	/// This method queries the BoringTun bridge for the current tunnel statistics,
	/// including handshake timing, byte counts, and network quality metrics.
	///
	/// If no tunnel exists yet (before start() is called), returns default empty
	/// statistics with all values at zero.
	///
	/// - Returns: Current tunnel statistics
	/// - Throws: EngineError.processingFailed if statistics retrieval fails
	func statistics() async throws -> TunnelStatus {
		do {
			let bridgeStats = try await bridge.statistics()
			return TunnelStatus(bridgeStatistics: bridgeStats)
		} catch let error as BridgeError {
			// If no tunnel exists yet, return empty statistics
			if error == .invalidHandle {
				let emptyCStats = stats(
					time_since_last_handshake: -1,
					tx_bytes: 0,
					rx_bytes: 0,
					estimated_loss: 0.0,
					estimated_rtt: -1,
					reserved: (
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0
					)
				)
				let emptyStats = TunnelStatistics(cStats: emptyCStats)
				return TunnelStatus(bridgeStatistics: emptyStats)
			}
			throw EngineError.processingFailed(error)
		} catch {
			throw EngineError.processingFailed(error)
		}
	}
}
