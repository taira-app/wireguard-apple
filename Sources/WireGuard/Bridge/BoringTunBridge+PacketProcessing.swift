// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation

// MARK: - Packet Processing

extension BoringTunBridge {
	/// Processes an outbound IP packet for transmission over the network.
	///
	/// This encrypts a plaintext IP packet (IPv4 or IPv6) into a WireGuard protocol
	/// packet that can be sent over UDP to the peer. It calls BoringTun's
	/// `wireguard_write()` FFI function.
	///
	/// ## Parameters
	///
	/// - Parameter packet: The plaintext IP packet to encrypt
	/// - Parameter destination: Buffer to write the encrypted WireGuard packet into
	///
	/// ## Returns
	///
	/// A `WireGuardResult` indicating what action to take:
	/// - `.writeToNetwork`: Send the encrypted data to the peer
	/// - `.done`: Packet processed but no output (e.g., handshake timing)
	/// - `.error`: Processing failed
	///
	/// ## Throws
	///
	/// - `BridgeError.invalidHandle`: No tunnel is active
	/// - `BridgeError.operationFailed`: BoringTun returned an error result
	///
	/// ## Buffer Size
	///
	/// The destination buffer should be at least `packet.count + 64` bytes to
	/// accommodate WireGuard overhead (typically 32 bytes for encryption + headers).
	/// A safe size is 65600 bytes (64KB + overhead).
	///
	/// ## Example
	///
	/// ```swift
	/// var networkBuffer = [UInt8](repeating: 0, count: 65600)
	/// let result = try await bridge.processOutboundPacket(
	///     ipPacket,
	///     into: &networkBuffer
	/// )
	///
	/// if result.operation == .writeToNetwork {
	///     try await udpSocket.send(networkBuffer.prefix(result.size))
	/// }
	/// ```
	public func processOutboundPacket(
		_ packet: Data,
		into destination: inout [UInt8]
	) throws -> WireGuardResult {
		guard let handle = tunnelHandle else {
			throw BridgeError.invalidHandle
		}

		// Call BoringTun's wireguard_write() to encrypt the packet.
		// This takes the plaintext IP packet and produces an encrypted WireGuard packet.
		// Capture destination.count before withUnsafeMutableBytes to avoid overlapping access.
		let destinationCount = destination.count
		let cResult = destination.withUnsafeMutableBytes { destBuffer in
			packet.withUnsafeBytes { sourceBuffer in
				wireguard_write(
					handle,
					sourceBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
					UInt32(packet.count),
					destBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
					UInt32(destinationCount)
				)
			}
		}

		// Convert the C result to Swift
		let result = WireGuardResult(cResult: cResult)

		// Check if the operation failed
		if result.operation == .error {
			throw BridgeError.operationFailed("Outbound packet processing failed")
		}

		return result
	}

	/// Processes an inbound WireGuard packet from the network.
	///
	/// This decrypts a WireGuard protocol packet received over UDP into a plaintext
	/// IP packet that can be delivered to the tunnel interface. It calls BoringTun's
	/// `wireguard_read()` FFI function.
	///
	/// ## Parameters
	///
	/// - Parameter packet: The encrypted WireGuard packet from the network
	/// - Parameter destination: Buffer to write the decrypted IP packet into
	///
	/// ## Returns
	///
	/// A `WireGuardResult` indicating what action to take:
	/// - `.writeToTunnelIPv4`/`.writeToTunnelIPv6`: Deliver decrypted packet to tunnel
	/// - `.writeToNetwork`: Send handshake response to peer
	/// - `.done`: Packet processed (e.g., handshake completed)
	/// - `.error`: Processing failed (bad auth, replay, etc.)
	///
	/// ## Throws
	///
	/// - `BridgeError.invalidHandle`: No tunnel is active
	/// - `BridgeError.operationFailed`: BoringTun returned an error result
	///
	/// ## Example
	///
	/// ```swift
	/// var ipBuffer = [UInt8](repeating: 0, count: 65536)
	/// let result = try await bridge.processInboundPacket(
	///     wireguardPacket,
	///     into: &ipBuffer
	/// )
	///
	/// switch result.operation {
	/// case .writeToTunnelIPv4, .writeToTunnelIPv6:
	///     try await packetFlow.write(ipBuffer.prefix(result.size))
	/// case .writeToNetwork:
	///     try await udpSocket.send(ipBuffer.prefix(result.size))
	/// default:
	///     break
	/// }
	/// ```
	public func processInboundPacket(
		_ packet: Data,
		into destination: inout [UInt8]
	) throws -> WireGuardResult {
		guard let handle = tunnelHandle else {
			throw BridgeError.invalidHandle
		}

		// Call BoringTun's wireguard_read() to decrypt the packet.
		// This takes an encrypted WireGuard packet and produces a plaintext IP packet.
		// Capture destination.count before withUnsafeMutableBytes to avoid overlapping access.
		let destinationCount = destination.count
		let cResult = destination.withUnsafeMutableBytes { destBuffer in
			packet.withUnsafeBytes { sourceBuffer in
				wireguard_read(
					handle,
					sourceBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
					UInt32(packet.count),
					destBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
					UInt32(destinationCount)
				)
			}
		}

		// Convert the C result to Swift
		let result = WireGuardResult(cResult: cResult)

		// Check if the operation failed
		if result.operation == .error {
			throw BridgeError.operationFailed("Inbound packet processing failed")
		}

		return result
	}

	/// Performs periodic tunnel maintenance.
	///
	/// This should be called approximately every 100 milliseconds to allow BoringTun
	/// to perform housekeeping tasks like:
	/// - Sending keepalive packets
	/// - Initiating handshake rekeying
	/// - Timing out stale sessions
	///
	/// It calls BoringTun's `wireguard_tick()` FFI function.
	///
	/// ## Parameters
	///
	/// - Parameter destination: Buffer to write any output packets into (e.g., keepalives)
	///
	/// ## Returns
	///
	/// A `WireGuardResult` indicating what action to take:
	/// - `.writeToNetwork`: Send keepalive or rekey packet to peer
	/// - `.done`: No action needed this tick
	///
	/// ## Throws
	///
	/// - `BridgeError.invalidHandle`: No tunnel is active
	///
	/// ## Example
	///
	/// ```swift
	/// // Call from a timer every 100ms
	/// Timer.publish(every: 0.1, on: .main, in: .common)
	///     .autoconnect()
	///     .sink { _ in
	///         Task {
	///             var buffer = [UInt8](repeating: 0, count: 256)
	///             let result = try await bridge.tick(into: &buffer)
	///             if result.operation == .writeToNetwork {
	///                 try await udpSocket.send(buffer.prefix(result.size))
	///             }
	///         }
	///     }
	/// ```
	public func tick(into destination: inout [UInt8]) throws -> WireGuardResult {
		guard let handle = tunnelHandle else {
			throw BridgeError.invalidHandle
		}

		// Call BoringTun's wireguard_tick() for periodic maintenance.
		// Capture destination.count before withUnsafeMutableBytes to avoid overlapping access.
		let destinationCount = destination.count
		let cResult = destination.withUnsafeMutableBytes { destBuffer in
			wireguard_tick(
				handle,
				destBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
				UInt32(destinationCount)
			)
		}

		return WireGuardResult(cResult: cResult)
	}

	/// Forces an immediate handshake with the peer.
	///
	/// This initiates a new handshake regardless of the current session state.
	/// Useful for:
	/// - Forcing rekey before the automatic 120-second interval
	/// - Recovering from suspected crypto failures
	/// - Testing connectivity
	///
	/// It calls BoringTun's `wireguard_force_handshake()` FFI function.
	///
	/// ## Parameters
	///
	/// - Parameter destination: Buffer to write the handshake initiation packet into
	///
	/// ## Returns
	///
	/// A `WireGuardResult` with `.writeToNetwork` operation containing the
	/// handshake initiation message to send to the peer.
	///
	/// ## Throws
	///
	/// - `BridgeError.invalidHandle`: No tunnel is active
	///
	/// ## Buffer Size
	///
	/// The destination buffer must be at least 148 bytes to hold a WireGuard
	/// handshake initiation message.
	///
	/// ## Example
	///
	/// ```swift
	/// var handshakeBuffer = [UInt8](repeating: 0, count: 256)
	/// let result = try await bridge.forceHandshake(into: &handshakeBuffer)
	/// try await udpSocket.send(handshakeBuffer.prefix(result.size))
	/// ```
	public func forceHandshake(into destination: inout [UInt8]) throws -> WireGuardResult {
		guard let handle = tunnelHandle else {
			throw BridgeError.invalidHandle
		}

		// Call BoringTun's wireguard_force_handshake().
		// Capture destination.count before withUnsafeMutableBytes to avoid overlapping access.
		let destinationCount = destination.count
		let cResult = destination.withUnsafeMutableBytes { destBuffer in
			wireguard_force_handshake(
				handle,
				destBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
				UInt32(destinationCount)
			)
		}

		return WireGuardResult(cResult: cResult)
	}
}
