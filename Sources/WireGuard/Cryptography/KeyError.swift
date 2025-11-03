import Foundation

/// Errors that can occur during cryptographic key operations.
///
/// These errors cover key generation, validation, encoding, and decoding operations
/// for WireGuard cryptographic keys (private keys, public keys, and preshared keys).
public enum KeyError: Error, LocalizedError, Sendable, Equatable {
	/// The key format is invalid or cannot be recognized.
	///
	/// This typically occurs when attempting to parse a key from a string that doesn't
	/// match expected formats (base64 or hexadecimal).
	case invalidFormat

	/// The key length is incorrect.
	///
	/// WireGuard keys must be exactly 32 bytes. This error is returned when a key
	/// has a different length.
	case invalidLength

	/// The base64 encoding is invalid or malformed.
	///
	/// This occurs when attempting to decode a base64 string that contains invalid
	/// characters or incorrect padding.
	case invalidBase64

	/// The hexadecimal encoding is invalid or malformed.
	///
	/// This occurs when attempting to decode a hex string that contains non-hexadecimal
	/// characters or has an incorrect length.
	case invalidHex

	/// The key consists entirely of zero bytes.
	///
	/// All-zero keys are cryptographically invalid for WireGuard and are rejected
	/// to prevent security issues.
	case allZeros

	/// Key generation failed.
	///
	/// This occurs when the underlying cryptographic random number generator fails
	/// to produce a valid key.
	case generationFailed

	/// A user-friendly description of the error.
	public var errorDescription: String? {
		switch self {
		case .invalidFormat:
			return "The key format is invalid."
		case .invalidLength:
			return "The key length is incorrect. WireGuard keys must be exactly 32 bytes."
		case .invalidBase64:
			return "The base64 encoding is invalid or malformed."
		case .invalidHex:
			return "The hexadecimal encoding is invalid or malformed."
		case .allZeros:
			return "The key consists entirely of zero bytes and is cryptographically invalid."
		case .generationFailed:
			return "Failed to generate a cryptographic key."
		}
	}

	/// Suggested recovery options for the user.
	public var recoverySuggestion: String? {
		switch self {
		case .invalidFormat:
			return "Ensure the key is provided in base64 or hexadecimal format."
		case .invalidLength:
			return "Verify the key data is exactly 32 bytes in length."
		case .invalidBase64:
			return
				"Check that the base64 string contains only valid characters (A-Z, a-z, 0-9, +, /) and proper padding."
		case .invalidHex:
			return
				"Check that the hex string contains only valid hexadecimal characters (0-9, A-F, a-f) "
				+ "and is 64 characters long."
		case .allZeros:
			return "Generate a new random key or use a key with non-zero bytes."
		case .generationFailed:
			return "Try generating the key again. If the problem persists, check system entropy sources."
		}
	}

	/// Technical explanation of why the error occurred.
	public var failureReason: String? {
		switch self {
		case .invalidFormat:
			return "The provided string could not be parsed as a valid key format."
		case .invalidLength:
			return
				"The decoded key data has an incorrect byte length. Expected 32 bytes for WireGuard X25519 keys."
		case .invalidBase64:
			return "The base64 decoder failed to parse the input string."
		case .invalidHex:
			return "The hexadecimal decoder failed to parse the input string."
		case .allZeros:
			return
				"All bytes in the key are zero, which is cryptographically weak and prohibited "
				+ "by the WireGuard specification."
		case .generationFailed:
			return "The cryptographic random number generator failed to produce key material."
		}
	}
}
