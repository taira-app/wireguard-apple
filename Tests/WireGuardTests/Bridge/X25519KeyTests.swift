// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTunFFI
import Foundation
import XCTest

@testable import WireGuard

/// Tests for X25519Key FFI bridge type.
///
/// X25519Key provides conversion between Swift's Data type and BoringTun's
/// C x25519_key structure. These tests verify:
/// - Correct 32-byte size validation
/// - Bidirectional conversion between Swift and C types
/// - Data preservation during round-trip conversions
/// - Sendable and Equatable conformance
final class X25519KeyTests: XCTestCase {
	// MARK: - Initialization from Data Tests

	/// Tests successful initialization with exactly 32 bytes.
	///
	/// x25519 keys are always exactly 32 bytes per the Curve25519 specification.
	/// This is the only valid initialization case.
	func testInitWithValid32Bytes() {
		// Create 32 bytes of test data
		let validData = Data(repeating: 0x42, count: 32)

		// Should successfully create a key
		let key = X25519Key(data: validData)

		XCTAssertNotNil(key, "Should create key with 32 bytes")
		XCTAssertEqual(key?.bytes, validData, "Key bytes should match input data")
	}

	/// Tests initialization failure with too few bytes.
	///
	/// Any data shorter than 32 bytes is invalid for x25519 and should
	/// return nil rather than creating a malformed key.
	func testInitWithTooFewBytes() {
		// Try various sizes less than 32
		let testSizes = [0, 1, 16, 31]

		for size in testSizes {
			let data = Data(repeating: 0x42, count: size)
			let key = X25519Key(data: data)

			XCTAssertNil(key, "Should not create key with \(size) bytes")
		}
	}

	/// Tests initialization failure with too many bytes.
	///
	/// Any data longer than 32 bytes is invalid for x25519 and should
	/// return nil. We don't silently truncate - the caller must provide
	/// exactly 32 bytes.
	func testInitWithTooManyBytes() {
		// Try various sizes greater than 32
		let testSizes = [33, 64, 100]

		for size in testSizes {
			let data = Data(repeating: 0x42, count: size)
			let key = X25519Key(data: data)

			XCTAssertNil(key, "Should not create key with \(size) bytes")
		}
	}

	// MARK: - C FFI Conversion Tests

	/// Tests creating X25519Key from BoringTun's C x25519_key structure.
	///
	/// This internal initializer is used when receiving keys from BoringTun
	/// FFI functions. It must correctly copy the 32 bytes from the C struct's
	/// inline array into Swift's Data type.
	func testInitFromCKey() {
		// Create a C key structure with known data
		var cKey = x25519_key()
		for i in 0..<32 {
			withUnsafeMutableBytes(of: &cKey.key) { buffer in
				buffer[i] = UInt8(i)  // Fill with 0, 1, 2, ..., 31
			}
		}

		// Convert to Swift key
		let swiftKey = X25519Key(cKey: cKey)

		// Verify the bytes were copied correctly
		XCTAssertEqual(swiftKey.bytes.count, 32, "Key should have 32 bytes")

		for i in 0..<32 {
			XCTAssertEqual(
				swiftKey.bytes[i],
				UInt8(i),
				"Byte at index \(i) should be \(i)"
			)
		}
	}

	/// Tests converting X25519Key to BoringTun's C x25519_key structure.
	///
	/// This internal method is used when passing keys to BoringTun FFI functions.
	/// It must correctly copy Swift's Data bytes into the C struct's inline array.
	func testConvertToCKey() {
		// Create a Swift key with known data
		var keyData = Data(count: 32)
		for i in 0..<32 {
			keyData[i] = UInt8(i)  // Fill with 0, 1, 2, ..., 31
		}
		let swiftKey = X25519Key(data: keyData)!

		// Convert to C key
		let cKey = swiftKey.toCKey()

		// Verify the bytes were copied correctly
		withUnsafeBytes(of: cKey.key) { buffer in
			for i in 0..<32 {
				XCTAssertEqual(
					buffer[i],
					UInt8(i),
					"Byte at index \(i) should be \(i)"
				)
			}
		}
	}

	/// Tests round-trip conversion: Swift -> C -> Swift.
	///
	/// Converting from Swift to C and back to Swift must preserve the exact
	/// byte values. This is critical for maintaining key integrity across the
	/// FFI boundary.
	func testRoundTripConversion() {
		// Create original Swift key with random-like data
		var originalData = Data(count: 32)
		for i in 0..<32 {
			originalData[i] = UInt8((i * 7 + 13) % 256)  // Pseudo-random pattern
		}
		let originalKey = X25519Key(data: originalData)!

		// Convert to C and back to Swift
		let cKey = originalKey.toCKey()
		let roundTrippedKey = X25519Key(cKey: cKey)

		// Verify data is identical
		XCTAssertEqual(
			roundTrippedKey.bytes,
			originalKey.bytes,
			"Round-trip conversion should preserve all bytes"
		)
	}

	/// Tests round-trip conversion: C -> Swift -> C.
	///
	/// Converting from C to Swift and back to C must preserve the exact
	/// byte values in the opposite direction.
	func testRoundTripConversionFromC() {
		// Create original C key with known data
		var originalCKey = x25519_key()
		for i in 0..<32 {
			withUnsafeMutableBytes(of: &originalCKey.key) { buffer in
				buffer[i] = UInt8((i * 3 + 7) % 256)  // Different pattern
			}
		}

		// Convert to Swift and back to C
		let swiftKey = X25519Key(cKey: originalCKey)
		let roundTrippedCKey = swiftKey.toCKey()

		// Verify bytes are identical
		withUnsafeBytes(of: originalCKey.key) { originalBuffer in
			withUnsafeBytes(of: roundTrippedCKey.key) { roundTrippedBuffer in
				for i in 0..<32 {
					XCTAssertEqual(
						roundTrippedBuffer[i],
						originalBuffer[i],
						"Byte at index \(i) should be preserved"
					)
				}
			}
		}
	}

	// MARK: - Edge Case Tests

	/// Tests that all-zero bytes are valid.
	///
	/// While an all-zero private key would be cryptographically weak,
	/// the FFI bridge should accept any 32-byte value. Higher-level
	/// cryptography code handles validation.
	func testAllZeroBytes() {
		let zeroData = Data(repeating: 0x00, count: 32)
		let key = X25519Key(data: zeroData)

		XCTAssertNotNil(key, "Should accept all-zero bytes")
		XCTAssertEqual(key?.bytes, zeroData)
	}

	/// Tests that all-ones bytes are valid.
	///
	/// Similarly, all-ones should be structurally accepted even if
	/// cryptographically unusual.
	func testAllOnesBytes() {
		let onesData = Data(repeating: 0xFF, count: 32)
		let key = X25519Key(data: onesData)

		XCTAssertNotNil(key, "Should accept all-ones bytes")
		XCTAssertEqual(key?.bytes, onesData)
	}

	// MARK: - Sendable Conformance Tests

	/// Tests that X25519Key conforms to Sendable protocol.
	///
	/// X25519Key must be Sendable because it's passed to and from actor methods
	/// in BoringTunBridge. This test verifies it can cross actor boundaries.
	func testSendableConformance() async {
		// Create a key in one isolation domain
		let data = Data(repeating: 0x42, count: 32)
		let key = X25519Key(data: data)!

		// Send to another isolation domain
		await Task {
			// If this compiles without Sendable warnings, conformance is correct
			let _ = key
		}.value
	}

	// MARK: - Equatable Tests

	/// Tests that X25519Key implements Equatable correctly.
	///
	/// Equatable is important for comparing keys in tests and for detecting
	/// configuration changes. Two keys are equal if their bytes are identical.
	func testEquality() {
		// Create two keys with identical data
		let data1 = Data(repeating: 0x42, count: 32)
		let key1 = X25519Key(data: data1)!

		let data2 = Data(repeating: 0x42, count: 32)
		let key2 = X25519Key(data: data2)!

		// Identical keys are equal
		XCTAssertEqual(key1, key2)

		// Create a key with different data
		let data3 = Data(repeating: 0x43, count: 32)
		let key3 = X25519Key(data: data3)!

		// Different keys are not equal
		XCTAssertNotEqual(key1, key3)

		// Keys differing by a single byte are not equal
		var data4 = Data(repeating: 0x42, count: 32)
		data4[0] = 0x43  // Change first byte only
		let key4 = X25519Key(data: data4)!

		XCTAssertNotEqual(key1, key4)
	}
}
