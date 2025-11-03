import Foundation
import Testing

@testable import WireGuard

/// Tests for the PresharedKey class.
///
/// These tests verify preshared key generation, encoding/decoding, and validation
/// functionality for WireGuard preshared keys.
struct PresharedKeyTests {
	// MARK: - Test fixtures

	/// A valid 32-byte preshared key for testing.
	let validKeyBytes = Data([
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	])

	// MARK: - Key generation tests

	@Test("PresharedKey generates new random key")
	func generateNewRandomKey() throws {
		let key = PresharedKey()

		// Verify key was created
		#expect(key.rawValue.count == 32)

		// Verify it's not all zeros
		#expect(key.rawValue != Data(repeating: 0, count: 32))
	}

	@Test("PresharedKey generates different keys")
	func generateDifferentKeys() throws {
		let key1 = PresharedKey()
		let key2 = PresharedKey()

		// Verify keys are different (extremely unlikely to be the same)
		#expect(key1.rawValue != key2.rawValue)
		#expect(key1 != key2)
	}

	@Test("PresharedKey generation produces valid keys")
	func generationProducesValidKeys() throws {
		// Generate multiple keys and verify they're all valid
		for _ in 0..<10 {
			let key = PresharedKey()
			#expect(key.rawValue.count == 32)
			#expect(key.rawValue != Data(repeating: 0, count: 32))
		}
	}

	// MARK: - Initialization tests

	@Test("PresharedKey initializes from valid raw data")
	func initializeFromValidRawData() throws {
		let key = PresharedKey(rawValue: validKeyBytes)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PresharedKey rejects all-zero data")
	func rejectAllZeroData() throws {
		let allZeros = Data(repeating: 0, count: 32)
		let key = PresharedKey(rawValue: allZeros)

		#expect(key == nil)
	}

	@Test("PresharedKey rejects invalid length")
	func rejectInvalidLength() throws {
		let tooShort = Data(repeating: 0x01, count: 16)
		let key = PresharedKey(rawValue: tooShort)

		#expect(key == nil)
	}

	// MARK: - Base64 encoding tests

	@Test("PresharedKey initializes from valid base64")
	func initializeFromValidBase64() throws {
		let base64 = validKeyBytes.base64EncodedString()
		let key = PresharedKey(base64Key: base64)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PresharedKey rejects invalid base64")
	func rejectInvalidBase64() throws {
		let key = PresharedKey(base64Key: "not valid base64!!!")
		#expect(key == nil)
	}

	@Test("PresharedKey round-trips through base64")
	func roundTripThroughBase64() throws {
		let key1 = PresharedKey()
		let base64 = key1.base64Key
		let key2 = try #require(PresharedKey(base64Key: base64))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Hexadecimal encoding tests

	@Test("PresharedKey initializes from valid hex")
	func initializeFromValidHex() throws {
		let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		let key = PresharedKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PresharedKey rejects invalid hex")
	func rejectInvalidHex() throws {
		let key = PresharedKey(hexKey: "invalid hex string")
		#expect(key == nil)
	}

	@Test("PresharedKey round-trips through hex")
	func roundTripThroughHex() throws {
		let key1 = PresharedKey()
		let hex = key1.hexKey
		let key2 = try #require(PresharedKey(hexKey: hex))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Equality tests

	@Test("PresharedKey equals itself")
	func keyEqualsItself() throws {
		let key = PresharedKey()
		#expect(key == key)
	}

	@Test("PresharedKey with same data are equal")
	func keysWithSameDataAreEqual() throws {
		let key1 = try #require(PresharedKey(rawValue: validKeyBytes))
		let key2 = try #require(PresharedKey(rawValue: validKeyBytes))

		#expect(key1 == key2)
	}

	@Test("PresharedKey with different data are not equal")
	func keysWithDifferentDataAreNotEqual() throws {
		let key1 = PresharedKey()
		let key2 = PresharedKey()

		// Extremely unlikely to be the same, but verify just in case
		if key1.rawValue != key2.rawValue {
			#expect(key1 != key2)
		}
	}

	// MARK: - Optional usage tests

	@Test("PresharedKey can be used as optional")
	func keyCanBeUsedAsOptional() throws {
		var optionalKey: PresharedKey?

		// Verify nil initially
		#expect(optionalKey == nil)

		// Assign a key
		optionalKey = PresharedKey()

		// Verify not nil
		#expect(optionalKey != nil)
		#expect(optionalKey?.rawValue.count == 32)
	}
}
