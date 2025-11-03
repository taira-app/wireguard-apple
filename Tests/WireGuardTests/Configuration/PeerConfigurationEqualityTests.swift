// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for PeerConfiguration equality and hashing semantics.
///
/// These tests verify that peer configurations properly implement Equatable and Hashable,
/// with special handling for statistics fields that are excluded from equality checks.
@Suite("Peer configuration equality tests")
struct PeerConfigurationEqualityTests {

	// MARK: - Test fixtures

	/// Creates a valid public key for testing.
	func makePublicKey() -> PublicKey {
		return PrivateKey().publicKey
	}

	/// Creates a valid preshared key for testing.
	func makePresharedKey() -> PresharedKey {
		return PresharedKey()
	}

	/// Creates a valid endpoint for testing.
	func makeEndpoint() throws -> Endpoint {
		return try #require(Endpoint(from: "192.168.1.1:51820"))
	}

	/// Creates a valid IPv4 address range for testing.
	func makeIPv4AddressRange() throws -> IPAddressRange {
		return try #require(IPAddressRange(from: "10.0.0.0/24"))
	}

	/// Creates a valid IPv6 address range for testing.
	func makeIPv6AddressRange() throws -> IPAddressRange {
		return try #require(IPAddressRange(from: "fd00::/64"))
	}

	// MARK: - Equatable tests

	/// Test that peers with same configuration are equal.
	///
	/// Equatable should compare configuration fields but ignore statistics.
	@Test("Peers with same configuration are equal")
	func peersWithSameConfigurationAreEqual() throws {
		// Given: two peers with same configuration
		let publicKey = makePublicKey()
		let endpoint = try makeEndpoint()
		let allowedIP = try makeIPv4AddressRange()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.endpoint = endpoint
		peer1.allowedIPs = [allowedIP]
		peer1.persistentKeepalive = 25

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.endpoint = endpoint
		peer2.allowedIPs = [allowedIP]
		peer2.persistentKeepalive = 25

		// Then: peers are equal
		#expect(peer1 == peer2)
	}

	/// Test that peers with different public keys are not equal.
	///
	/// Different public keys mean different peer identities.
	@Test("Peers with different public keys are not equal")
	func peersWithDifferentPublicKeysAreNotEqual() throws {
		// Given: two peers with different public keys
		let peer1 = PeerConfiguration(publicKey: makePublicKey())
		let peer2 = PeerConfiguration(publicKey: makePublicKey())

		// Then: peers are not equal
		#expect(peer1 != peer2)
	}

	/// Test that statistics do not affect equality.
	///
	/// Two peers with same configuration but different statistics should
	/// still be equal because statistics are runtime state, not configuration.
	@Test("Statistics do not affect equality")
	func statisticsDoNotAffectEquality() throws {
		// Given: two peers with same configuration but different statistics
		let publicKey = makePublicKey()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.receivedBytes = 1000
		peer1.transmittedBytes = 2000
		peer1.lastHandshakeTime = Date()

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.receivedBytes = 3000
		peer2.transmittedBytes = 4000
		peer2.lastHandshakeTime = Date().addingTimeInterval(-100)

		// Then: peers are still equal (statistics ignored)
		#expect(peer1 == peer2)
	}

	/// Test that peers with different endpoints are not equal.
	///
	/// Different endpoints mean different network destinations.
	@Test("Peers with different endpoints are not equal")
	func peersWithDifferentEndpointsAreNotEqual() throws {
		// Given: two peers with different endpoints
		let publicKey = makePublicKey()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.endpoint = try #require(Endpoint(from: "192.168.1.1:51820"))

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.endpoint = try #require(Endpoint(from: "192.168.1.2:51820"))

		// Then: peers are not equal
		#expect(peer1 != peer2)
	}

	/// Test that peers with different allowed IPs are not equal.
	///
	/// Different allowed IPs mean different routing configuration.
	@Test("Peers with different allowed IPs are not equal")
	func peersWithDifferentAllowedIPsAreNotEqual() throws {
		// Given: two peers with different allowed IPs
		let publicKey = makePublicKey()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.allowedIPs = [try makeIPv4AddressRange()]

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.allowedIPs = [try makeIPv6AddressRange()]

		// Then: peers are not equal
		#expect(peer1 != peer2)
	}

	// MARK: - Hashable tests

	/// Test that peers hash based on public key only.
	///
	/// Hash value should be determined solely by the public key, allowing
	/// peers to be used in sets and dictionaries keyed by identity.
	@Test("Peers hash based on public key only")
	func peersHashByPublicKey() throws {
		// Given: two peers with same public key but different configuration
		let publicKey = makePublicKey()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.endpoint = try makeEndpoint()

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.allowedIPs = [try makeIPv4AddressRange()]

		// Then: peers have same hash value
		#expect(peer1.hashValue == peer2.hashValue)
	}

	/// Test that peers with different public keys have different hashes.
	///
	/// Different public keys should produce different hash values for
	/// efficient set/dictionary operations.
	@Test("Peers with different public keys have different hashes")
	func peersWithDifferentPublicKeysHaveDifferentHashes() throws {
		// Given: two peers with different public keys
		let peer1 = PeerConfiguration(publicKey: makePublicKey())
		let peer2 = PeerConfiguration(publicKey: makePublicKey())

		// Then: peers should have different hash values
		// Note: Hash collisions are theoretically possible but astronomically unlikely
		#expect(peer1.hashValue != peer2.hashValue)
	}

	/// Test that peers can be used in a Set.
	///
	/// Hashable conformance allows peers to be stored in sets, with
	/// uniqueness determined by public key.
	@Test("Peers can be used in a Set")
	func peersCanBeUsedInSet() throws {
		// Given: multiple peers with some duplicates
		let publicKey1 = makePublicKey()
		let publicKey2 = makePublicKey()

		var peer1a = PeerConfiguration(publicKey: publicKey1)
		peer1a.endpoint = try makeEndpoint()

		var peer1b = PeerConfiguration(publicKey: publicKey1)
		peer1b.allowedIPs = [try makeIPv4AddressRange()]

		let peer2 = PeerConfiguration(publicKey: publicKey2)

		// When: adding to a set
		let peerSet: Set<PeerConfiguration> = [peer1a, peer1b, peer2]

		// Then: set contains unique peers by public key
		#expect(peerSet.count == 2)  // peer1a and peer1b are duplicates
	}

	/// Test that statistics do not affect hash value.
	///
	/// Since statistics don't affect equality, they shouldn't affect
	/// hash values either.
	@Test("Statistics do not affect hash value")
	func statisticsDoNotAffectHashValue() throws {
		// Given: two peers with same public key but different statistics
		let publicKey = makePublicKey()

		var peer1 = PeerConfiguration(publicKey: publicKey)
		peer1.receivedBytes = 1000

		var peer2 = PeerConfiguration(publicKey: publicKey)
		peer2.receivedBytes = 9999

		// Then: hash values are identical
		#expect(peer1.hashValue == peer2.hashValue)
	}

	// MARK: - Sendable conformance test

	/// Test that PeerConfiguration conforms to Sendable.
	///
	/// Sendable conformance is required for Swift 6 concurrency.
	@Test("PeerConfiguration conforms to Sendable")
	func conformsToSendable() throws {
		// Given: a peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// When: passing to an async context
		Task {
			// Then: peer can be sent across concurrency boundaries
			_ = peer
		}
	}
}
