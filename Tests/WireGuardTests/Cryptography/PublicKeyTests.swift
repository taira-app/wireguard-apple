import Foundation
import Testing

@testable import WireGuard

/// Tests for the PublicKey class.
///
/// These tests verify public key initialization, encoding/decoding, and hashing
/// functionality for WireGuard public keys.
struct PublicKeyTests {
	// MARK: - Test fixtures

	/// A valid 32-byte public key for testing.
	let validKeyBytes = Data([
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	])

	// MARK: - Initialization tests

	@Test("PublicKey initializes from valid raw data")
	func initializeFromValidRawData() throws {
		let key = PublicKey(rawValue: validKeyBytes)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PublicKey rejects all-zero data")
	func rejectAllZeroData() throws {
		let allZeros = Data(repeating: 0, count: 32)
		let key = PublicKey(rawValue: allZeros)

		#expect(key == nil)
	}

	@Test("PublicKey rejects invalid length")
	func rejectInvalidLength() throws {
		let tooShort = Data(repeating: 0x01, count: 16)
		let key = PublicKey(rawValue: tooShort)

		#expect(key == nil)
	}

	// MARK: - Base64 encoding tests

	@Test("PublicKey initializes from valid base64")
	func initializeFromValidBase64() throws {
		let base64 = validKeyBytes.base64EncodedString()
		let key = PublicKey(base64Key: base64)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PublicKey rejects invalid base64")
	func rejectInvalidBase64() throws {
		let key = PublicKey(base64Key: "not valid base64!!!")
		#expect(key == nil)
	}

	@Test("PublicKey round-trips through base64")
	func roundTripThroughBase64() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let base64 = key1.base64Key
		let key2 = try #require(PublicKey(base64Key: base64))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Hexadecimal encoding tests

	@Test("PublicKey initializes from valid hex")
	func initializeFromValidHex() throws {
		let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		let key = PublicKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PublicKey rejects invalid hex")
	func rejectInvalidHex() throws {
		let key = PublicKey(hexKey: "invalid hex string")
		#expect(key == nil)
	}

	@Test("PublicKey round-trips through hex")
	func roundTripThroughHex() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let hex = key1.hexKey
		let key2 = try #require(PublicKey(hexKey: hex))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Equality tests

	@Test("PublicKey equals itself")
	func keyEqualsItself() throws {
		let key = try #require(PublicKey(rawValue: validKeyBytes))
		#expect(key == key)
	}

	@Test("PublicKey with same data are equal")
	func keysWithSameDataAreEqual() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let key2 = try #require(PublicKey(rawValue: validKeyBytes))

		#expect(key1 == key2)
	}

	@Test("PublicKey with different data are not equal")
	func keysWithDifferentDataAreNotEqual() throws {
		let data1 = Data(repeating: 0x01, count: 32)
		let data2 = Data(repeating: 0x02, count: 32)

		let key1 = try #require(PublicKey(rawValue: data1))
		let key2 = try #require(PublicKey(rawValue: data2))

		#expect(key1 != key2)
	}

	// MARK: - Hashing tests

	@Test("PublicKey can be hashed")
	func keyCanBeHashed() throws {
		let key = try #require(PublicKey(rawValue: validKeyBytes))

		var hasher = Hasher()
		key.hash(into: &hasher)
		let hash = hasher.finalize()

		#expect(hash != 0)  // Hash should not be zero
	}

	@Test("PublicKey with same data have same hash")
	func keysWithSameDataHaveSameHash() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let key2 = try #require(PublicKey(rawValue: validKeyBytes))

		var hasher1 = Hasher()
		key1.hash(into: &hasher1)
		let hash1 = hasher1.finalize()

		var hasher2 = Hasher()
		key2.hash(into: &hasher2)
		let hash2 = hasher2.finalize()

		#expect(hash1 == hash2)
	}

	@Test("PublicKey can be used in a Set")
	func keyCanBeUsedInSet() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let key2 = try #require(PublicKey(rawValue: Data(repeating: 0x02, count: 32)))

		var set = Set<PublicKey>()
		set.insert(key1)
		set.insert(key2)

		#expect(set.count == 2)
		#expect(set.contains(key1))
		#expect(set.contains(key2))
	}

	@Test("PublicKey can be used as Dictionary key")
	func keyCanBeUsedAsDictionaryKey() throws {
		let key1 = try #require(PublicKey(rawValue: validKeyBytes))
		let key2 = try #require(PublicKey(rawValue: Data(repeating: 0x02, count: 32)))

		var dict: [PublicKey: String] = [:]
		dict[key1] = "first"
		dict[key2] = "second"

		#expect(dict.count == 2)
		#expect(dict[key1] == "first")
		#expect(dict[key2] == "second")
	}

	// MARK: - Integration with PrivateKey tests

	@Test("PublicKey derived from PrivateKey is valid")
	func publicKeyDerivedFromPrivateKeyIsValid() throws {
		let privateKey = PrivateKey()
		let publicKey = privateKey.publicKey

		// Verify the public key is valid
		#expect(publicKey.rawValue.count == 32)
		#expect(publicKey.rawValue != Data(repeating: 0, count: 32))
	}

	@Test("Derived PublicKey can be encoded and decoded")
	func derivedPublicKeyCanBeEncodedAndDecoded() throws {
		let privateKey = PrivateKey()
		let publicKey = privateKey.publicKey

		// Encode to base64 and decode
		let base64 = publicKey.base64Key
		let decodedKey = try #require(PublicKey(base64Key: base64))

		#expect(decodedKey == publicKey)
		#expect(decodedKey.rawValue == publicKey.rawValue)
	}
}
