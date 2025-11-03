// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation

/// A 32-byte x25519 Curve25519 cryptographic key for FFI interop.
///
/// This type provides a Swift wrapper around BoringTun's `x25519_key` C structure,
/// enabling safe conversion between Swift's Data type and the C representation
/// required by BoringTun FFI functions.
///
/// The same 32-byte representation is used for both private keys (scalars) and
/// public keys (curve points) at the FFI layer. Higher-level Cryptography domain
/// types (PrivateKey, PublicKey) provide semantic distinction and use this type
/// internally for FFI communication.
///
/// ## Purpose
///
/// This type exists purely for FFI boundary crossing. It handles:
/// - Converting Swift Data to C struct for FFI calls
/// - Converting C struct results back to Swift Data
/// - Ensuring correct 32-byte size constraint
///
/// ## Usage
///
/// Typically used internally by Bridge and Cryptography domains:
///
/// ```swift
/// // In BoringTunBridge - call FFI with C key
/// let cKey = x25519Key.toCKey()
/// let result = x25519_public_key(cKey)
/// let publicKey = X25519Key(cKey: result)
/// ```
public struct X25519Key: Sendable, Equatable {
	/// The raw 32-byte key material.
	///
	/// For private keys, this is the scalar value used in the x25519 function.
	/// For public keys, this is the encoded curve point.
	///
	/// x25519 keys are always exactly 32 bytes per the Curve25519 specification.
	public let bytes: Data

	/// Creates an x25519 key from raw byte data.
	///
	/// The data must be exactly 32 bytes. If it's shorter or longer, initialization
	/// fails and returns nil. No cryptographic validation is performed - any 32 bytes
	/// are structurally accepted.
	///
	/// - Parameter data: The raw 32-byte key material.
	/// - Returns: An x25519 key, or nil if data length is not exactly 32 bytes.
	public init?(data: Data) {
		// x25519 keys must be exactly 32 bytes per the Curve25519 specification
		guard data.count == 32 else { return nil }
		self.bytes = data
	}

	/// Creates an x25519 key from BoringTun's C FFI key structure.
	///
	/// This converts the C `x25519_key` struct, which contains a 32-byte inline array,
	/// into Swift's Data type. The conversion is a memory copy from the C struct.
	///
	/// - Parameter cKey: The C key structure from a BoringTun FFI function.
	internal init(cKey: x25519_key) {
		// The x25519_key C struct contains: struct x25519_key { uint8_t key[32]; }
		// We use withUnsafeBytes to safely access the struct's memory without
		// creating dangling pointers or violating Swift's memory safety.
		var mutableKey = cKey
		self.bytes = withUnsafeBytes(of: &mutableKey.key) { buffer in
			Data(buffer)
		}
	}

	/// Converts this Swift key into BoringTun's C FFI key structure.
	///
	/// This creates a new C `x25519_key` struct and copies the 32 bytes from
	/// this Swift key's Data into the C struct's inline array. The resulting
	/// structure can be passed directly to BoringTun FFI functions.
	///
	/// - Returns: A C key structure containing this key's bytes.
	internal func toCKey() -> x25519_key {
		// Create a new C struct: struct x25519_key { uint8_t key[32]; }
		var cKey = x25519_key()

		// Copy our Data bytes into the C struct's array.
		// We use unsafe APIs here to bridge between Swift's managed memory (Data)
		// and C's raw memory (fixed-size array).
		bytes.withUnsafeBytes { buffer in
			// Bind the buffer to UInt8 to match the C array type
			let source = buffer.bindMemory(to: UInt8.self)

			// Get a mutable pointer to the C struct's array
			withUnsafeMutableBytes(of: &cKey.key) { destination in
				// Copy exactly 32 bytes from source to destination
				destination.copyBytes(from: source)
			}
		}

		return cKey
	}
}
