import Foundation
import Testing

@testable import WireGuard

/// Tests for the PrivateKey class.
///
/// These tests verify private key generation, public key derivation, and
/// encoding/decoding functionality specific to WireGuard private keys.
struct PrivateKeyTests {
	// MARK: - Test fixtures

	/// A valid 32-byte private key for testing.
	let validKeyBytes = Data([
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
	])

	// MARK: - Key generation tests

	@Test("PrivateKey generates new random key")
	func generateNewRandomKey() throws {
		let key = PrivateKey()

		// Verify key was created
		#expect(key.rawValue.count == 32)

		// Verify it's not all zeros
		#expect(key.rawValue != Data(repeating: 0, count: 32))
	}

	@Test("PrivateKey generates different keys")
	func generateDifferentKeys() throws {
		let key1 = PrivateKey()
		let key2 = PrivateKey()

		// Verify keys are different (extremely unlikely to be the same)
		#expect(key1.rawValue != key2.rawValue)
		#expect(key1 != key2)
	}

	@Test("PrivateKey generation produces valid keys")
	func generationProducesValidKeys() throws {
		// Generate multiple keys and verify they're all valid
		for _ in 0..<10 {
			let key = PrivateKey()
			#expect(key.rawValue.count == 32)
			#expect(key.rawValue != Data(repeating: 0, count: 32))
		}
	}

	// MARK: - Public key derivation tests

	@Test("PrivateKey derives public key")
	func derivePublicKey() throws {
		let privateKey = PrivateKey()
		let publicKey = privateKey.publicKey

		// Verify public key was derived
		#expect(publicKey.rawValue.count == 32)

		// Verify it's not all zeros
		#expect(publicKey.rawValue != Data(repeating: 0, count: 32))
	}

	@Test("PrivateKey derives consistent public key")
	func deriveConsistentPublicKey() throws {
		let privateKey = PrivateKey()

		// Derive public key multiple times
		let publicKey1 = privateKey.publicKey
		let publicKey2 = privateKey.publicKey

		// Verify they're the same
		#expect(publicKey1 == publicKey2)
		#expect(publicKey1.rawValue == publicKey2.rawValue)
	}

	@Test("Different private keys produce different public keys")
	func differentPrivateKeysProduceDifferentPublicKeys() throws {
		let privateKey1 = PrivateKey()
		let privateKey2 = PrivateKey()

		let publicKey1 = privateKey1.publicKey
		let publicKey2 = privateKey2.publicKey

		// Verify public keys are different
		#expect(publicKey1 != publicKey2)
		#expect(publicKey1.rawValue != publicKey2.rawValue)
	}

	@Test("Same private key data produces same public key")
	func samePrivateKeyDataProducesSamePublicKey() throws {
		let privateKey1 = try #require(PrivateKey(rawValue: validKeyBytes))
		let privateKey2 = try #require(PrivateKey(rawValue: validKeyBytes))

		let publicKey1 = privateKey1.publicKey
		let publicKey2 = privateKey2.publicKey

		// Verify public keys are the same
		#expect(publicKey1 == publicKey2)
		#expect(publicKey1.rawValue == publicKey2.rawValue)
	}

	// MARK: - Initialization tests

	@Test("PrivateKey initializes from valid raw data")
	func initializeFromValidRawData() throws {
		let key = PrivateKey(rawValue: validKeyBytes)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PrivateKey rejects all-zero data")
	func rejectAllZeroData() throws {
		let allZeros = Data(repeating: 0, count: 32)
		let key = PrivateKey(rawValue: allZeros)

		#expect(key == nil)
	}

	@Test("PrivateKey rejects invalid length")
	func rejectInvalidLength() throws {
		let tooShort = Data(repeating: 0x01, count: 16)
		let key = PrivateKey(rawValue: tooShort)

		#expect(key == nil)
	}

	// MARK: - Base64 encoding tests

	@Test("PrivateKey initializes from valid base64")
	func initializeFromValidBase64() throws {
		let base64 = validKeyBytes.base64EncodedString()
		let key = PrivateKey(base64Key: base64)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PrivateKey rejects invalid base64")
	func rejectInvalidBase64() throws {
		let key = PrivateKey(base64Key: "not valid base64!!!")
		#expect(key == nil)
	}

	@Test("PrivateKey round-trips through base64")
	func roundTripThroughBase64() throws {
		let key1 = PrivateKey()
		let base64 = key1.base64Key
		let key2 = try #require(PrivateKey(base64Key: base64))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Hexadecimal encoding tests

	@Test("PrivateKey initializes from valid hex")
	func initializeFromValidHex() throws {
		let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		let key = PrivateKey(hexKey: hex)

		#expect(key != nil)
		#expect(key?.rawValue == validKeyBytes)
	}

	@Test("PrivateKey rejects invalid hex")
	func rejectInvalidHex() throws {
		let key = PrivateKey(hexKey: "invalid hex string")
		#expect(key == nil)
	}

	@Test("PrivateKey round-trips through hex")
	func roundTripThroughHex() throws {
		let key1 = PrivateKey()
		let hex = key1.hexKey
		let key2 = try #require(PrivateKey(hexKey: hex))

		#expect(key1.rawValue == key2.rawValue)
		#expect(key1 == key2)
	}

	// MARK: - Equality tests

	@Test("PrivateKey equals itself")
	func keyEqualsItself() throws {
		let key = PrivateKey()
		#expect(key == key)
	}

	@Test("PrivateKey with same data are equal")
	func keysWithSameDataAreEqual() throws {
		let key1 = try #require(PrivateKey(rawValue: validKeyBytes))
		let key2 = try #require(PrivateKey(rawValue: validKeyBytes))

		#expect(key1 == key2)
	}

	@Test("PrivateKey with different data are not equal")
	func keysWithDifferentDataAreNotEqual() throws {
		let key1 = PrivateKey()
		let key2 = PrivateKey()

		// Extremely unlikely to be the same, but verify just in case
		if key1.rawValue != key2.rawValue {
			#expect(key1 != key2)
		}
	}
}
