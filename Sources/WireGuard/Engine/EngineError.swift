// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Errors that can occur during tunnel engine operations.
///
/// The engine layer orchestrates the WireGuard tunnel lifecycle, including
/// initialization, packet processing, and state management. These errors
/// represent failures at the engine level, distinct from lower-level bridge
/// errors or higher-level configuration errors.
///
/// ## Error categories
///
/// **Lifecycle errors**: Occur during tunnel start/stop operations
/// - `notConfigured`: Tunnel missing required configuration
/// - `alreadyRunning`: Attempted to start already-running tunnel
/// - `notRunning`: Attempted operation on stopped tunnel
///
/// **Packet processing errors**: Occur during data transfer
/// - `invalidPacket`: Malformed or invalid packet data
/// - `processingFailed`: Packet encryption/decryption failed
///
/// **Network errors**: Occur during network operations
/// - `endpointResolutionFailed`: Could not resolve peer endpoint hostname
/// - `handshakeFailed`: WireGuard handshake could not complete
///
/// ## Example usage
///
/// ```swift
/// do {
///     try await tunnel.start()
/// } catch let error as EngineError {
///     switch error {
///     case .alreadyRunning:
///         // Tunnel is already active, no action needed
///         break
///     case .endpointResolutionFailed(let hostname):
///         logger.error("Cannot resolve \(hostname)")
///     case .handshakeFailed(let reason):
///         logger.error("Handshake failed: \(reason)")
///     default:
///         logger.error("Engine error: \(error.localizedDescription)")
///     }
/// }
/// ```
public enum EngineError: Error, Sendable, Equatable {
	/// The tunnel is not configured and cannot be started.
	///
	/// This error occurs when attempting to start a tunnel that has not been
	/// properly initialized with a configuration. Ensure the tunnel has a valid
	/// TunnelConfiguration before starting.
	case notConfigured

	/// The tunnel is already running and cannot be started again.
	///
	/// This error occurs when calling start() on a tunnel that is already in
	/// the connected or starting state. Stop the tunnel first before attempting
	/// to restart it.
	case alreadyRunning

	/// The tunnel is not running and the requested operation requires it to be active.
	///
	/// This error occurs when attempting packet processing or other operations
	/// that require an active tunnel, but the tunnel is in the stopped or stopping
	/// state. Start the tunnel before performing these operations.
	case notRunning

	/// A packet is malformed or invalid and cannot be processed.
	///
	/// This error occurs when the tunnel receives data that does not conform to
	/// the expected format. The associated data contains the invalid packet bytes
	/// for debugging purposes.
	///
	/// - Parameter packet: The malformed packet data that caused the error
	case invalidPacket(Data)

	/// Packet processing failed during encryption or decryption.
	///
	/// This error wraps a lower-level error from the BoringTun bridge that occurred
	/// during packet processing. The associated error provides details about what
	/// went wrong.
	///
	/// - Parameter underlyingError: The underlying error from packet processing
	case processingFailed(Error)

	/// Failed to resolve the peer endpoint hostname to an IP address.
	///
	/// This error occurs when DNS resolution fails for a peer endpoint that uses
	/// a hostname instead of an IP address. Network connectivity issues, DNS
	/// server problems, or invalid hostnames can cause this error.
	///
	/// - Parameter hostname: The hostname that could not be resolved
	case endpointResolutionFailed(String)

	/// The WireGuard handshake failed to complete.
	///
	/// This error occurs when the cryptographic handshake with the peer fails.
	/// Common causes include incorrect keys, network issues preventing handshake
	/// packets from reaching the peer, or peer-side configuration problems.
	///
	/// - Parameter reason: A description of why the handshake failed
	case handshakeFailed(String)
}

// MARK: - Equatable conformance

extension EngineError {
	public static func == (lhs: EngineError, rhs: EngineError) -> Bool {
		switch (lhs, rhs) {
		case (.notConfigured, .notConfigured),
			(.alreadyRunning, .alreadyRunning),
			(.notRunning, .notRunning):
			return true

		case (.invalidPacket(let lhsData), .invalidPacket(let rhsData)):
			return lhsData == rhsData

		case (.processingFailed(let lhsError), .processingFailed(let rhsError)):
			// Compare error descriptions since Error doesn't conform to Equatable
			return String(describing: lhsError) == String(describing: rhsError)

		case (.endpointResolutionFailed(let lhsHostname), .endpointResolutionFailed(let rhsHostname)):
			return lhsHostname == rhsHostname

		case (.handshakeFailed(let lhsReason), .handshakeFailed(let rhsReason)):
			return lhsReason == rhsReason

		default:
			return false
		}
	}
}
