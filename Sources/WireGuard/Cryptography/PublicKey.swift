import Foundation

/// A WireGuard public key used for peer identification.
///
/// Public keys are x25519 curve points derived from private keys. They uniquely
/// identify WireGuard peers and are used for key exchange during handshakes.
///
/// Public keys are safe to share and are typically exchanged between peers during
/// WireGuard configuration.
///
/// ## Derivation
///
/// Public keys are derived from private keys:
///
/// ```swift
/// let privateKey = PrivateKey()
/// let publicKey = privateKey.publicKey
/// ```
///
/// ## Initialization
///
/// Public keys can be initialized from base64 or hex strings:
///
/// ```swift
/// let publicKey = PublicKey(base64Key: "base64EncodedString...")
/// let publicKey = PublicKey(hexKey: "hex encoded string...")
/// ```
///
/// ## Thread safety
///
/// This class is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public final class PublicKey: BaseKey, @unchecked Sendable {
	/// Creates a public key from raw binary data.
	///
	/// The data must be exactly 32 bytes and must not consist entirely of zeros.
	///
	/// - Parameter rawValue: The 32-byte public key data.
	/// - Returns: A public key instance, or `nil` if the data is invalid.
	public override init?(rawValue: Data) {
		super.init(rawValue: rawValue)
	}

	/// Creates a public key from a base64-encoded string.
	///
	/// This is the standard format used in WireGuard configuration files.
	///
	/// - Parameter base64Key: A base64-encoded public key string.
	/// - Returns: A public key instance, or `nil` if the string is invalid.
	public convenience init?(base64Key: String) {
		guard let data = Data(base64Encoded: base64Key) else {
			return nil
		}

		self.init(rawValue: data)
	}

	/// Creates a public key from a hexadecimal string.
	///
	/// The hex string must be exactly 64 characters (32 bytes).
	///
	/// - Parameter hexKey: A hexadecimal-encoded public key string.
	/// - Returns: A public key instance, or `nil` if the string is invalid.
	public convenience init?(hexKey: String) {
		// Remove any whitespace and convert to lowercase
		let cleaned = hexKey.replacingOccurrences(of: " ", with: "").lowercased()

		// Validate length (64 hex chars = 32 bytes)
		guard cleaned.count == BaseKey.keyLength * 2 else {
			return nil
		}

		// Validate hex characters
		guard cleaned.allSatisfy({ $0.isHexDigit }) else {
			return nil
		}

		// Convert hex string to data
		var data = Data(capacity: BaseKey.keyLength)
		var index = cleaned.startIndex

		for _ in 0..<BaseKey.keyLength {
			let nextIndex = cleaned.index(index, offsetBy: 2)
			let byteString = cleaned[index..<nextIndex]

			guard let byte = UInt8(byteString, radix: 16) else {
				return nil
			}

			data.append(byte)
			index = nextIndex
		}

		self.init(rawValue: data)
	}
}

// MARK: - Character Extension

extension Character {
	/// Checks if the character is a valid hexadecimal digit.
	fileprivate var isHexDigit: Bool {
		isASCII && (isNumber || ("a"..."f").contains(self) || ("A"..."F").contains(self))
	}
}
