import Foundation
import Testing

@testable import WireGuard

/// Tests for the BaseKey class.
///
/// These tests verify the base functionality for all WireGuard cryptographic keys
/// including initialization, encoding/decoding, validation, equality, and hashing.
struct BaseKeyTests {
	// MARK: - Test fixtures

	/// A valid 32-byte key for testing.
	let validKeyBytes = Data([
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	])

	/// All-zero key bytes (invalid).
	let allZeroBytes = Data(repeating: 0, count: 32)

	/// Too short key bytes (invalid).
	let tooShortBytes = Data(repeating: 0x01, count: 16)

	/// Too long key bytes (invalid).
	let tooLongBytes = Data(repeating: 0x01, count: 64)

	// MARK: - Initialization tests

	@Test("BaseKey initializes with valid raw data")
	func initializeWithValidRawData() throws {
		let key = BaseKey(rawValue: validKeyBytes)
		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("BaseKey rejects all-zero data")
	func rejectAllZeroData() throws {
		let key = BaseKey(rawValue: allZeroBytes)
		#expect(key == nil)
	}

	@Test("BaseKey rejects data that is too short")
	func rejectTooShortData() throws {
		let key = BaseKey(rawValue: tooShortBytes)
		#expect(key == nil)
	}

	@Test("BaseKey rejects data that is too long")
	func rejectTooLongData() throws {
		let key = BaseKey(rawValue: tooLongBytes)
		#expect(key == nil)
	}

	// MARK: - Base64 encoding tests

	@Test("BaseKey encodes to base64")
	func encodeToBase64() throws {
		let key = try #require(BaseKey(rawValue: validKeyBytes))
		let base64 = key.base64Key

		// Verify base64 string is not empty
		#expect(!base64.isEmpty)

		// Verify we can decode it back
		let decoded = Data(base64Encoded: base64)
		#expect(decoded == validKeyBytes)
	}

	@Test("BaseKey initializes from valid base64")
	func initializeFromValidBase64() throws {
		let base64 = validKeyBytes.base64EncodedString()
		let key = BaseKey(base64Key: base64)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("BaseKey rejects invalid base64")
	func rejectInvalidBase64() throws {
		let key = BaseKey(base64Key: "not a valid base64 string!!!")
		#expect(key == nil)
	}

	@Test("BaseKey rejects base64 with wrong length")
	func rejectBase64WithWrongLength() throws {
		// Base64 that decodes to 16 bytes instead of 32
		let shortBase64 = Data(repeating: 0x01, count: 16).base64EncodedString()
		let key = BaseKey(base64Key: shortBase64)
		#expect(key == nil)
	}

	@Test("BaseKey round-trips through base64")
	func roundTripThroughBase64() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let base64 = key1.base64Key
		let key2 = try #require(BaseKey(base64Key: base64))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Hexadecimal encoding tests

	@Test("BaseKey encodes to hex")
	func encodeToHex() throws {
		let key = try #require(BaseKey(rawValue: validKeyBytes))
		let hex = key.hexKey

		// Verify hex string has correct length (64 chars for 32 bytes)
		#expect(hex.count == 64)

		// Verify all characters are valid hex
		#expect(hex.allSatisfy { $0.isHexDigit })
	}

	@Test("BaseKey initializes from valid hex")
	func initializeFromValidHex() throws {
		let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		let key = BaseKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("BaseKey initializes from hex with uppercase")
	func initializeFromHexWithUppercase() throws {
		let hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
		let key = BaseKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("BaseKey initializes from hex with spaces")
	func initializeFromHexWithSpaces() throws {
		let hex =
			"01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20"
		let key = BaseKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("BaseKey rejects invalid hex characters")
	func rejectInvalidHexCharacters() throws {
		let key = BaseKey(hexKey: "gg" + String(repeating: "00", count: 31))
		#expect(key == nil)
	}

	@Test("BaseKey rejects hex with wrong length")
	func rejectHexWithWrongLength() throws {
		let key = BaseKey(hexKey: "0102030405")  // Only 5 bytes worth
		#expect(key == nil)
	}

	@Test("BaseKey round-trips through hex")
	func roundTripThroughHex() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let hex = key1.hexKey
		let key2 = try #require(BaseKey(hexKey: hex))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Equality tests

	@Test("BaseKey equals itself")
	func keyEqualsItself() throws {
		let key = try #require(BaseKey(rawValue: validKeyBytes))
		#expect(key == key)
	}

	@Test("BaseKey with same data are equal")
	func keysWithSameDataAreEqual() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let key2 = try #require(BaseKey(rawValue: validKeyBytes))

		#expect(key1 == key2)
	}

	@Test("BaseKey with different data are not equal")
	func keysWithDifferentDataAreNotEqual() throws {
		let data1 = Data(repeating: 0x01, count: 32)
		let data2 = Data(repeating: 0x02, count: 32)

		let key1 = try #require(BaseKey(rawValue: data1))
		let key2 = try #require(BaseKey(rawValue: data2))

		#expect(key1 != key2)
	}

	// MARK: - Hashing tests

	@Test("BaseKey can be hashed")
	func keyCanBeHashed() throws {
		let key = try #require(BaseKey(rawValue: validKeyBytes))

		var hasher = Hasher()
		key.hash(into: &hasher)
		let hash = hasher.finalize()

		#expect(hash != 0)  // Hash should not be zero
	}

	@Test("BaseKey with same data have same hash")
	func keysWithSameDataHaveSameHash() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let key2 = try #require(BaseKey(rawValue: validKeyBytes))

		var hasher1 = Hasher()
		key1.hash(into: &hasher1)
		let hash1 = hasher1.finalize()

		var hasher2 = Hasher()
		key2.hash(into: &hasher2)
		let hash2 = hasher2.finalize()

		#expect(hash1 == hash2)
	}

	@Test("BaseKey can be used in a Set")
	func keyCanBeUsedInSet() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let key2 = try #require(BaseKey(rawValue: Data(repeating: 0x02, count: 32)))

		var set = Set<BaseKey>()
		set.insert(key1)
		set.insert(key2)

		#expect(set.count == 2)
		#expect(set.contains(key1))
		#expect(set.contains(key2))
	}

	@Test("BaseKey can be used as Dictionary key")
	func keyCanBeUsedAsDictionaryKey() throws {
		let key1 = try #require(BaseKey(rawValue: validKeyBytes))
		let key2 = try #require(BaseKey(rawValue: Data(repeating: 0x02, count: 32)))

		var dict: [BaseKey: String] = [:]
		dict[key1] = "first"
		dict[key2] = "second"

		#expect(dict.count == 2)
		#expect(dict[key1] == "first")
		#expect(dict[key2] == "second")
	}
}

// MARK: - Character Extension

extension Character {
	/// Checks if the character is a valid hexadecimal digit.
	fileprivate var isHexDigit: Bool {
		isASCII && (isNumber || ("a"..."f").contains(self) || ("A"..."F").contains(self))
	}
}
