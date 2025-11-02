// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Errors that occur during BoringTun FFI operations.
///
/// These errors represent failures in the communication layer between Swift
/// and BoringTun's Rust implementation. They cover issues like invalid tunnel
/// state, memory allocation failures, and packet processing errors.
///
/// Each error includes localized descriptions to help with debugging and
/// user-facing error messages in network extension logs.
public enum BridgeError: Error, LocalizedError, Sendable, Equatable {
	/// Failed to create a new tunnel instance.
	///
	/// This typically occurs when BoringTun's `new_tunnel` FFI function
	/// returns null, indicating that the Rust side could not allocate
	/// or initialize the tunnel structure. Possible causes include:
	/// - Invalid cryptographic keys provided
	/// - Memory allocation failure
	/// - Internal Rust panic or assertion failure
	case tunnelCreationFailed

	/// Attempted to use an invalid or deallocated tunnel handle.
	///
	/// This error indicates a programming error where a tunnel operation
	/// was attempted on a handle that is null or has been freed. This should
	/// never happen in correct code due to Swift's actor isolation protecting
	/// the tunnel handle lifetime.
	case invalidHandle

	/// A packet processing operation failed.
	///
	/// BoringTun returned an error result when attempting to encrypt an
	/// outbound packet or decrypt an inbound packet. This can occur when:
	/// - Packet authentication fails (decryption)
	/// - Packet is malformed or truncated
	/// - Internal state machine is in an invalid state
	/// - Associated data contains the specific error details if available
	case operationFailed(String?)

	/// An invalid cryptographic key was provided.
	///
	/// The key validation function rejected the provided base64-encoded key.
	/// This happens when the key is not properly formatted, has incorrect
	/// length, or contains invalid base64 characters.
	case invalidKey

	/// An invalid packet was provided for processing.
	///
	/// The packet data is malformed, too short, too long, or otherwise
	/// fails basic validation before encryption/decryption can be attempted.
	case invalidPacket

	/// A memory-related error occurred during FFI operations.
	///
	/// This indicates a failure allocating or managing memory for buffers
	/// used in FFI calls. This is rare and typically indicates a serious
	/// system-level issue like memory exhaustion.
	case memoryError

	// MARK: - LocalizedError conformance

	/// A localized message describing what error occurred.
	public var errorDescription: String? {
		switch self {
		case .tunnelCreationFailed:
			return "Failed to create WireGuard tunnel"
		case .invalidHandle:
			return "Invalid tunnel handle"
		case .operationFailed(let details):
			if let details = details {
				return "Tunnel operation failed: \(details)"
			}
			return "Tunnel operation failed"
		case .invalidKey:
			return "Invalid cryptographic key"
		case .invalidPacket:
			return "Invalid packet data"
		case .memoryError:
			return "Memory allocation error"
		}
	}

	/// A localized message describing the reason for the failure.
	public var failureReason: String? {
		switch self {
		case .tunnelCreationFailed:
			return "The BoringTun library could not initialize a new tunnel instance. " +
				"This may be due to invalid keys or insufficient system resources."
		case .invalidHandle:
			return "Attempted to use a tunnel that has been deallocated or was never properly created."
		case .operationFailed:
			return "The packet processing operation failed, possibly due to authentication failure, " +
				"invalid packet format, or internal state issues."
		case .invalidKey:
			return "The provided cryptographic key failed validation. Keys must be 32 bytes " +
				"encoded in base64 format."
		case .invalidPacket:
			return "The packet data is malformed or has invalid length for WireGuard processing."
		case .memoryError:
			return "Unable to allocate required memory for the operation."
		}
	}

	/// A localized message describing how to recover from the failure.
	public var recoverySuggestion: String? {
		switch self {
		case .tunnelCreationFailed:
			return "Verify that all cryptographic keys are valid base64-encoded 32-byte values. " +
				"Check system logs for additional details from BoringTun."
		case .invalidHandle:
			return "This is a programming error. Ensure tunnel operations only occur while " +
				"the tunnel is active and before it is deallocated."
		case .operationFailed:
			return "Retry the operation. If the problem persists, the peer may be using " +
				"incompatible keys or the network connection may be corrupted."
		case .invalidKey:
			return "Generate a new valid key using x25519_secret_key() or verify the key " +
				"is properly base64-encoded."
		case .invalidPacket:
			return "Verify the packet source is providing valid IP packets (IPv4 or IPv6) " +
				"or valid WireGuard protocol messages."
		case .memoryError:
			return "Close other applications to free system memory, or reduce the packet " +
				"buffer sizes if configured."
		}
	}
}
