// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation

/// The result of a WireGuard packet processing operation.
///
/// BoringTun's packet processing functions (`wireguard_write`, `wireguard_read`,
/// `wireguard_tick`, `wireguard_force_handshake`) return this type to indicate
/// what action the caller should take next.
///
/// The operation type determines whether output data was produced and where it
/// should be sent (network vs tunnel interface). The size field indicates how
/// many bytes were written to the output buffer.
///
/// ## Example Usage
///
/// ```swift
/// let result = try bridge.processOutboundPacket(ipPacket, into: &networkBuffer)
/// switch result.operation {
/// case .writeToNetwork:
///     // Send result.size bytes from networkBuffer over UDP
///     try await udpSocket.send(networkBuffer.prefix(result.size))
/// case .done:
///     // No output, operation completed
///     break
/// case .error:
///     throw BridgeError.operationFailed(nil)
/// }
/// ```
public struct WireGuardResult: Sendable, Equatable {
	/// The operation type indicating what action to take with the result.
	public let operation: ResultOperation

	/// The number of bytes written to the destination buffer.
	///
	/// For operations that produce output (`writeToNetwork`, `writeToTunnelIPv4`,
	/// `writeToTunnelIPv6`), this indicates how many bytes of the destination
	/// buffer contain valid data and should be processed.
	///
	/// For `done` and `error` operations, this is typically 0 as no data was produced.
	public let size: Int

	/// Creates a WireGuard result from BoringTun's C FFI result structure.
	///
	/// This converts the C `wireguard_result` type into a Swift-native structure,
	/// translating the operation enum and size field into Swift types.
	///
	/// - Parameter cResult: The C result structure from a BoringTun FFI function.
	internal init(cResult: wireguard_result) {
		// Convert the C enum to Swift enum, defaulting to .error if unknown value
		// The C enum result_type is imported as an enum, so we convert to UInt32
		self.operation = ResultOperation(rawValue: cResult.op.rawValue) ?? .error
		self.size = Int(cResult.size)
	}
}

/// The type of operation result from WireGuard packet processing.
///
/// This enum represents the different outcomes when processing WireGuard packets.
/// Each case indicates what the caller should do with the result data:
///
/// - **done**: Operation completed, no further action needed
/// - **writeToNetwork**: Send encrypted data over UDP to the peer
/// - **writeToTunnelIPv4/IPv6**: Deliver decrypted IP packet to the tunnel interface
/// - **error**: Operation failed, handle the error
///
/// The raw values match BoringTun's C enum definition in `wireguard_ffi.h`.
public enum ResultOperation: UInt32, Sendable, Equatable {
	/// Operation completed successfully with no output data.
	///
	/// This occurs when:
	/// - Processing a handshake message that doesn't require an immediate response
	/// - Calling `tick()` when no keepalive or rekey is needed
	/// - An operation completes but produces no network or tunnel output
	///
	/// The caller should continue normal operation without sending any data.
	case done = 0

	/// Encrypted WireGuard protocol data should be sent to the network.
	///
	/// The operation produced encrypted data that must be sent over UDP to the
	/// peer's endpoint. This includes:
	/// - Handshake initiation and response messages
	/// - Encrypted transport data packets
	/// - Keepalive messages
	///
	/// The caller should send the result data (up to `result.size` bytes) to
	/// the peer via the configured UDP socket.
	case writeToNetwork = 1

	/// An error occurred during the operation.
	///
	/// The operation failed and no valid output was produced. Common causes:
	/// - Packet authentication failure (invalid MAC tag)
	/// - Malformed or truncated input data
	/// - Invalid tunnel state for the requested operation
	/// - Replay protection rejected the packet
	///
	/// The caller should handle this as an error condition and should not
	/// attempt to use any data from the output buffer.
	case error = 2

	/// A decrypted IPv4 packet should be delivered to the tunnel interface.
	///
	/// The operation successfully decrypted an IPv4 packet from the peer.
	/// The result data (up to `result.size` bytes) contains a complete IPv4
	/// packet that should be written to the tunnel's packet flow.
	///
	/// The caller should pass this to the operating system's network stack
	/// via the NetworkExtension packet flow interface.
	case writeToTunnelIPv4 = 4

	/// A decrypted IPv6 packet should be delivered to the tunnel interface.
	///
	/// The operation successfully decrypted an IPv6 packet from the peer.
	/// The result data (up to `result.size` bytes) contains a complete IPv6
	/// packet that should be written to the tunnel's packet flow.
	///
	/// The caller should pass this to the operating system's network stack
	/// via the NetworkExtension packet flow interface.
	case writeToTunnelIPv6 = 6
}
