import Foundation

/// A WireGuard preshared key for additional security.
///
/// Preshared keys are optional 32-byte symmetric keys that provide an additional
/// layer of security to WireGuard tunnels. When configured, they are mixed into
/// the key derivation process during handshakes, providing post-quantum resistance.
///
/// Unlike private and public keys which use x25519 elliptic curve cryptography,
/// preshared keys are simply random 32-byte values.
///
/// ## Usage
///
/// Preshared keys are optional and must be configured on both peers:
///
/// ```swift
/// let presharedKey = PresharedKey()
/// ```
///
/// ## Security
///
/// Preshared keys should be:
/// - Generated using cryptographically secure random number generators
/// - Shared only between the two peers that will use them
/// - Kept secret like private keys
/// - Different for each peer pair
///
/// ## Encoding
///
/// Preshared keys can be encoded for storage or configuration:
///
/// ```swift
/// let base64String = presharedKey.base64Key
/// let hexString = presharedKey.hexKey
/// ```
///
/// ## Thread safety
///
/// This class is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public final class PresharedKey: BaseKey, @unchecked Sendable {
	/// Creates a new random preshared key.
	///
	/// This uses the system's cryptographically secure random number generator
	/// to produce a 32-byte random value.
	///
	/// The key is guaranteed to be cryptographically strong and suitable for
	/// use in WireGuard tunnels.
	public convenience init() {
		// Generate 32 random bytes using SecRandomCopyBytes
		var keyData = Data(count: BaseKey.keyLength)

		let result = keyData.withUnsafeMutableBytes { pointer in
			guard let baseAddress = pointer.baseAddress else {
				return errSecParam
			}
			return SecRandomCopyBytes(kSecRandomDefault, BaseKey.keyLength, baseAddress)
		}

		// Check if random generation succeeded
		guard result == errSecSuccess else {
			// This should never happen on modern systems
			fatalError("Failed to generate random preshared key")
		}

		// Initialize with the generated key
		// This should never fail since we just generated valid random data
		self.init(rawValue: keyData)!
	}

	/// Creates a preshared key from raw binary data.
	///
	/// The data must be exactly 32 bytes and must not consist entirely of zeros.
	///
	/// - Parameter rawValue: The 32-byte preshared key data.
	/// - Returns: A preshared key instance, or `nil` if the data is invalid.
	public override init?(rawValue: Data) {
		super.init(rawValue: rawValue)
	}

	/// Creates a preshared key from a base64-encoded string.
	///
	/// This is the standard format used in WireGuard configuration files.
	///
	/// - Parameter base64Key: A base64-encoded preshared key string.
	/// - Returns: A preshared key instance, or `nil` if the string is invalid.
	public convenience init?(base64Key: String) {
		guard let data = Data(base64Encoded: base64Key) else {
			return nil
		}

		self.init(rawValue: data)
	}

	/// Creates a preshared key from a hexadecimal string.
	///
	/// The hex string must be exactly 64 characters (32 bytes).
	///
	/// - Parameter hexKey: A hexadecimal-encoded preshared key string.
	/// - Returns: A preshared key instance, or `nil` if the string is invalid.
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

	deinit {
		// Note: Ideally we would zero the key memory here for security.
		// However, Swift's Data type uses copy-on-write semantics which
		// makes secure cleanup complex. The short lifetime of keys in
		// memory provides reasonable security in practice.
	}
}

// MARK: - Character Extension

extension Character {
	/// Checks if the character is a valid hexadecimal digit.
	fileprivate var isHexDigit: Bool {
		isASCII && (isNumber || ("a"..."f").contains(self) || ("A"..."F").contains(self))
	}
}
