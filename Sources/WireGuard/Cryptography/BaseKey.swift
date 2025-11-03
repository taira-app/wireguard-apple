import Foundation

/// Base class for WireGuard cryptographic keys.
///
/// This class provides common functionality for all WireGuard key types including
/// raw data storage, base64 and hexadecimal encoding/decoding, validation, and
/// equality/hashing operations.
///
/// WireGuard uses X25519 keys which are always 32 bytes in length. Keys must not
/// be all zeros as this is cryptographically invalid.
///
/// This class is thread-safe and conforms to `Sendable` for use in Swift 6
/// concurrent contexts.
public class BaseKey: @unchecked Sendable, Equatable, Hashable {
	/// The raw 32-byte key data.
	///
	/// This data represents the actual cryptographic key material in its binary form.
	public let rawValue: Data

	/// The key encoded as a base64 string.
	///
	/// This is the standard encoding format used in WireGuard configuration files.
	public var base64Key: String {
		rawValue.base64EncodedString()
	}

	/// The key encoded as a hexadecimal string.
	///
	/// This format is useful for debugging and some configuration scenarios.
	/// The hex string is lowercase and exactly 64 characters long.
	public var hexKey: String {
		rawValue.map { String(format: "%02x", $0) }.joined()
	}

	/// The required length for all WireGuard keys in bytes.
	public static let keyLength: Int = 32

	/// Creates a key from raw binary data.
	///
	/// The data must be exactly 32 bytes and must not consist entirely of zeros.
	///
	/// - Parameter rawValue: The 32-byte key data.
	/// - Returns: A key instance, or `nil` if the data is invalid.
	public init?(rawValue: Data) {
		// Validate length
		guard rawValue.count == Self.keyLength else {
			return nil
		}

		// Validate not all zeros
		guard !Self.isAllZeros(rawValue) else {
			return nil
		}

		self.rawValue = rawValue
	}

	/// Creates a key from a base64-encoded string.
	///
	/// The base64 string must decode to exactly 32 bytes and the resulting data
	/// must not be all zeros.
	///
	/// - Parameter base64Key: A base64-encoded key string.
	/// - Returns: A key instance, or `nil` if the string is invalid.
	public convenience init?(base64Key: String) {
		guard let data = Data(base64Encoded: base64Key) else {
			return nil
		}

		self.init(rawValue: data)
	}

	/// Creates a key from a hexadecimal string.
	///
	/// The hex string must be exactly 64 characters (32 bytes) and contain only
	/// valid hexadecimal digits (0-9, a-f, A-F). The resulting data must not be
	/// all zeros.
	///
	/// - Parameter hexKey: A hexadecimal-encoded key string.
	/// - Returns: A key instance, or `nil` if the string is invalid.
	public convenience init?(hexKey: String) {
		// Remove any whitespace and convert to lowercase
		let cleaned = hexKey.replacingOccurrences(of: " ", with: "").lowercased()

		// Validate length (64 hex chars = 32 bytes)
		guard cleaned.count == Self.keyLength * 2 else {
			return nil
		}

		// Validate hex characters
		guard cleaned.allSatisfy({ $0.isHexDigit }) else {
			return nil
		}

		// Convert hex string to data
		var data = Data(capacity: Self.keyLength)
		var index = cleaned.startIndex

		for _ in 0..<Self.keyLength {
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

	/// Checks if the provided data consists entirely of zero bytes.
	///
	/// - Parameter data: The data to check.
	/// - Returns: `true` if all bytes are zero, `false` otherwise.
	private static func isAllZeros(_ data: Data) -> Bool {
		data.allSatisfy { $0 == 0 }
	}

	// MARK: - Equatable

	/// Compares two keys for equality.
	///
	/// Keys are considered equal if their raw data is identical.
	///
	/// - Parameters:
	///   - lhs: The left-hand side key.
	///   - rhs: The right-hand side key.
	/// - Returns: `true` if the keys are equal, `false` otherwise.
	public static func == (lhs: BaseKey, rhs: BaseKey) -> Bool {
		lhs.rawValue == rhs.rawValue
	}

	// MARK: - Hashable

	/// Hashes the key for use in sets and dictionaries.
	///
	/// The hash is based on the raw key data.
	///
	/// - Parameter hasher: The hasher to use.
	public func hash(into hasher: inout Hasher) {
		hasher.combine(rawValue)
	}

	// MARK: - Cleanup

	deinit {
		// Note: Swift's automatic memory management handles Data cleanup.
		// For additional security, sensitive data could be zeroed here,
		// but Data's copy-on-write semantics make this complex.
		// In practice, the short lifetime of keys in memory provides
		// reasonable security.
	}
}

// MARK: - Character Extension

extension Character {
	/// Checks if the character is a valid hexadecimal digit.
	fileprivate var isHexDigit: Bool {
		isASCII && (isNumber || ("a"..."f").contains(self) || ("A"..."F").contains(self))
	}
}
