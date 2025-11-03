// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

// MARK: - Localized error conformance

extension EngineError: LocalizedError {
	/// A human-readable description of the error.
	///
	/// This provides a clear, user-facing message that explains what went wrong.
	/// The description is suitable for displaying in UI alerts or error messages.
	public var errorDescription: String? {
		switch self {
		case .notConfigured:
			return "The tunnel is not configured."

		case .alreadyRunning:
			return "The tunnel is already running."

		case .notRunning:
			return "The tunnel is not running."

		case .invalidPacket:
			return "Received an invalid packet that cannot be processed."

		case .processingFailed(let error):
			return "Packet processing failed: \(error.localizedDescription)"

		case .endpointResolutionFailed(let hostname):
			return "Could not resolve endpoint hostname '\(hostname)'."

		case .handshakeFailed(let reason):
			return "WireGuard handshake failed: \(reason)"
		}
	}

	/// A suggestion for how the user might recover from the error.
	///
	/// This provides actionable guidance on what steps to take to resolve the
	/// error condition. These suggestions are intended to help users fix the
	/// problem without requiring deep technical knowledge.
	public var recoverySuggestion: String? {
		switch self {
		case .notConfigured:
			return "Ensure the tunnel has a valid configuration with at least one peer before starting."

		case .alreadyRunning:
			return
				"Stop the tunnel before attempting to start it again, or check if the tunnel "
				+ "is already in the desired state."

		case .notRunning:
			return
				"Start the tunnel before attempting to process packets or perform operations "
				+ "that require an active connection."

		case .invalidPacket:
			return
				"This may indicate network corruption or an attack. Check network conditions and peer configuration."

		case .processingFailed:
			return
				"Check the tunnel configuration and ensure the peer is reachable. "
				+ "The connection may need to be restarted."

		case .endpointResolutionFailed:
			return
				"Check your network connection and DNS settings. Verify the hostname is correct "
				+ "and the DNS server is reachable."

		case .handshakeFailed:
			return
				"Verify the peer's public key is correct, check network connectivity, "
				+ "and ensure the peer is running and reachable."
		}
	}

	/// The underlying technical reason why the error occurred.
	///
	/// This provides more detailed information about the root cause of the error,
	/// which is useful for debugging and troubleshooting. This information is more
	/// technical than the error description and is intended for developers or logs.
	public var failureReason: String? {
		switch self {
		case .notConfigured:
			return
				"The tunnel was created but no configuration was provided, "
				+ "or the configuration was cleared before starting."

		case .alreadyRunning:
			return
				"The start() method was called on a tunnel that is already in the starting or connected state."

		case .notRunning:
			return
				"An operation requiring an active tunnel was attempted while the tunnel "
				+ "is in the stopped or stopping state."

		case .invalidPacket(let data):
			return
				"Received a packet with \(data.count) bytes that does not conform "
				+ "to expected format or protocol requirements."

		case .processingFailed(let error):
			return "The BoringTun bridge failed to process the packet with error: \(error)"

		case .endpointResolutionFailed(let hostname):
			return
				"DNS resolution failed for hostname '\(hostname)'. The DNS server may be unreachable, "
				+ "the hostname may not exist, or network connectivity may be unavailable."

		case .handshakeFailed(let reason):
			return "The cryptographic handshake with the peer did not complete successfully: \(reason)"
		}
	}
}
