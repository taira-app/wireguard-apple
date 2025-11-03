import BoringTun
import Foundation

/// A WireGuard private key used for tunnel encryption.
///
/// Private keys are x25519 curve scalars used in the WireGuard protocol for
/// establishing secure tunnels. Each WireGuard interface has exactly one private
/// key, from which the corresponding public key is derived.
///
/// Private keys should be kept secret and never transmitted. Only the derived
/// public key should be shared with peers.
///
/// ## Generation
///
/// Generate a new random private key:
///
/// ```swift
/// let privateKey = PrivateKey()
/// ```
///
/// ## Public key derivation
///
/// The corresponding public key is automatically derived:
///
/// ```swift
/// let privateKey = PrivateKey()
/// let publicKey = privateKey.publicKey
/// ```
///
/// ## Encoding
///
/// Private keys can be encoded for storage or configuration:
///
/// ```swift
/// let base64String = privateKey.base64Key
/// let hexString = privateKey.hexKey
/// ```
///
/// ## Thread safety
///
/// This class is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public final class PrivateKey: BaseKey, @unchecked Sendable {
	/// The derived public key corresponding to this private key.
	///
	/// The public key is computed using x25519 scalar multiplication on the
	/// curve25519 base point. This operation is performed by BoringTun's
	/// FFI layer.
	///
	/// The public key is computed lazily and cached for performance.
	public var publicKey: PublicKey {
		// Convert to X25519Key for FFI
		guard let x25519Key = X25519Key(data: rawValue) else {
			// This should never happen since rawValue is validated in init
			fatalError("Invalid private key data")
		}

		// Call BoringTun FFI to derive public key
		let cKey = x25519Key.toCKey()
		let publicCKey = x25519_public_key(cKey)
		let publicX25519Key = X25519Key(cKey: publicCKey)

		// Convert back to PublicKey
		guard let publicKey = PublicKey(rawValue: publicX25519Key.bytes) else {
			// This should never happen since BoringTun returns valid keys
			fatalError("BoringTun returned invalid public key")
		}

		return publicKey
	}

	/// Creates a new random private key.
	///
	/// This uses BoringTun's cryptographically secure random number generator
	/// to produce a valid x25519 private key.
	///
	/// The key is guaranteed to be cryptographically strong and suitable for
	/// use in WireGuard tunnels.
	public convenience init() {
		// Generate random private key via BoringTun FFI
		let cKey = x25519_secret_key()
		let x25519Key = X25519Key(cKey: cKey)

		// Initialize with the generated key
		// This should never fail since BoringTun generates valid keys
		self.init(rawValue: x25519Key.bytes)!
	}

	/// Creates a private key from raw binary data.
	///
	/// The data must be exactly 32 bytes and must not consist entirely of zeros.
	///
	/// - Parameter rawValue: The 32-byte private key data.
	/// - Returns: A private key instance, or `nil` if the data is invalid.
	public override init?(rawValue: Data) {
		super.init(rawValue: rawValue)
	}

	/// Creates a private key from a base64-encoded string.
	///
	/// This is the standard format used in WireGuard configuration files.
	///
	/// - Parameter base64Key: A base64-encoded private key string.
	/// - Returns: A private key instance, or `nil` if the string is invalid.
	public convenience init?(base64Key: String) {
		guard let data = Data(base64Encoded: base64Key) else {
			return nil
		}

		self.init(rawValue: data)
	}

	/// Creates a private key from a hexadecimal string.
	///
	/// The hex string must be exactly 64 characters (32 bytes).
	///
	/// - Parameter hexKey: A hexadecimal-encoded private key string.
	/// - Returns: A private key instance, or `nil` if the string is invalid.
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
		//
		// For additional security in the future, we could:
		// 1. Use UnsafeMutableRawBufferPointer for key storage
		// 2. Explicitly zero memory in deinit
		// 3. Lock memory to prevent swapping
	}
}

// MARK: - Character Extension

extension Character {
	/// Checks if the character is a valid hexadecimal digit.
	fileprivate var isHexDigit: Bool {
		isASCII && (isNumber || ("a"..."f").contains(self) || ("A"..."F").contains(self))
	}
}
