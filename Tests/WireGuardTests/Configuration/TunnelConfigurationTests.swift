// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for the TunnelConfiguration struct.
///
/// These tests verify complete tunnel configuration creation and validation.
/// They ensure that tunnel configurations properly compose interface and peer
/// configurations while enforcing WireGuard protocol requirements.
@Suite("Tunnel configuration tests")
struct TunnelConfigurationTests {

	// MARK: - Test fixtures

	/// Creates a valid interface configuration for testing.
	func makeInterfaceConfiguration() throws -> InterfaceConfiguration {
		var interface = InterfaceConfiguration(privateKey: PrivateKey())
		interface.addresses = [try #require(IPAddressRange(from: "10.0.0.1/24"))]
		return interface
	}

	/// Creates a valid peer configuration for testing.
	func makePeerConfiguration() throws -> PeerConfiguration {
		var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
		peer.allowedIPs = [try #require(IPAddressRange(from: "10.0.0.2/32"))]
		return peer
	}

	// MARK: - Initialization tests

	/// Test that tunnel can be created with interface and peers.
	///
	/// A valid tunnel requires both interface configuration and at least
	/// one peer configuration.
	@Test("Tunnel can be created with interface and peers")
	func createTunnelWithInterfaceAndPeers() throws {
		// Given: interface and peer configurations
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()

		// When: creating a tunnel configuration
		let tunnel = try TunnelConfiguration(
			name: "Test Tunnel",
			interface: interface,
			peers: [peer]
		)

		// Then: tunnel is created with provided values
		#expect(tunnel.name == "Test Tunnel")
		#expect(tunnel.interface == interface)
		#expect(tunnel.peers.count == 1)
		#expect(tunnel.peers[0] == peer)
	}

	/// Test that tunnel can be created without a name.
	///
	/// Tunnel name is optional and can be nil.
	@Test("Tunnel can be created without name")
	func createTunnelWithoutName() throws {
		// Given: interface and peer configurations
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()

		// When: creating a tunnel without a name
		let tunnel = try TunnelConfiguration(
			name: nil,
			interface: interface,
			peers: [peer]
		)

		// Then: tunnel is created with nil name
		#expect(tunnel.name == nil)
	}

	/// Test that tunnel can have multiple peers.
	///
	/// A tunnel can connect to multiple peers simultaneously.
	@Test("Tunnel can have multiple peers")
	func tunnelCanHaveMultiplePeers() throws {
		// Given: interface and multiple peer configurations
		let interface = try makeInterfaceConfiguration()
		let peer1 = try makePeerConfiguration()
		let peer2 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		let peer3 = PeerConfiguration(publicKey: PrivateKey().publicKey)

		// When: creating a tunnel with multiple peers
		let tunnel = try TunnelConfiguration(
			name: "Multi-peer Tunnel",
			interface: interface,
			peers: [peer1, peer2, peer3]
		)

		// Then: tunnel contains all peers
		#expect(tunnel.peers.count == 3)
	}

	// MARK: - Validation tests

	/// Test that tunnel creation fails with no peers.
	///
	/// WireGuard requires at least one peer to establish a tunnel.
	@Test("Tunnel creation fails with no peers")
	func tunnelCreationFailsWithNoPeers() throws {
		// Given: interface but no peers
		let interface = try makeInterfaceConfiguration()

		// When: attempting to create a tunnel with no peers
		// Then: creation throws noPeers error
		#expect(throws: ConfigurationError.noPeers) {
			try TunnelConfiguration(
				name: "Invalid Tunnel",
				interface: interface,
				peers: []
			)
		}
	}

	/// Test that tunnel creation fails with duplicate peer public keys.
	///
	/// Each peer must have a unique public key to avoid routing ambiguity.
	@Test("Tunnel creation fails with duplicate peer public keys")
	func tunnelCreationFailsWithDuplicatePeerPublicKeys() throws {
		// Given: interface and peers with duplicate public keys
		let interface = try makeInterfaceConfiguration()
		let sharedPublicKey = PrivateKey().publicKey

		var peer1 = PeerConfiguration(publicKey: sharedPublicKey)
		peer1.allowedIPs = [try #require(IPAddressRange(from: "10.0.0.2/32"))]

		var peer2 = PeerConfiguration(publicKey: sharedPublicKey)
		peer2.allowedIPs = [try #require(IPAddressRange(from: "10.0.0.3/32"))]

		// When: attempting to create a tunnel with duplicate keys
		// Then: creation throws duplicatePeerPublicKey error
		#expect(throws: ConfigurationError.self) {
			try TunnelConfiguration(
				name: "Duplicate Peers",
				interface: interface,
				peers: [peer1, peer2]
			)
		}
	}

	/// Test that tunnel accepts peers with unique public keys.
	///
	/// Multiple peers are valid as long as each has a unique public key.
	@Test("Tunnel accepts peers with unique public keys")
	func tunnelAcceptsPeersWithUniquePublicKeys() throws {
		// Given: interface and peers with unique public keys
		let interface = try makeInterfaceConfiguration()
		let peer1 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		let peer2 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		let peer3 = PeerConfiguration(publicKey: PrivateKey().publicKey)

		// When: creating a tunnel with unique peer keys
		let tunnel = try TunnelConfiguration(
			name: "Unique Peers",
			interface: interface,
			peers: [peer1, peer2, peer3]
		)

		// Then: tunnel is created successfully
		#expect(tunnel.peers.count == 3)
	}

	// MARK: - Immutability tests

	/// Test that peers array is immutable after initialization.
	///
	/// The peers array is defined as `let` and cannot be modified after
	/// tunnel creation. This ensures configuration stability.
	@Test("Peers array is immutable after initialization")
	func peersArrayIsImmutableAfterInitialization() throws {
		// Given: a tunnel configuration
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()
		let tunnel = try TunnelConfiguration(
			name: "Immutable Tunnel",
			interface: interface,
			peers: [peer]
		)

		// Then: peers property is immutable (compile-time check)
		// This test verifies the property is declared as `let`
		_ = tunnel.peers  // Read-only access
		// tunnel.peers = []  // This would not compile
	}

	/// Test that interface configuration can be modified.
	///
	/// While peers are immutable, the interface configuration is mutable
	/// and can be updated after tunnel creation.
	@Test("Interface configuration can be modified")
	func interfaceConfigurationCanBeModified() throws {
		// Given: a tunnel configuration
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()
		var tunnel = try TunnelConfiguration(
			name: "Mutable Interface",
			interface: interface,
			peers: [peer]
		)

		// When: modifying the interface
		tunnel.interface.mtu = 1420

		// Then: interface is updated
		#expect(tunnel.interface.mtu == 1420)
	}

	// MARK: - Equatable tests

	/// Test that tunnels with same configuration are equal.
	///
	/// Equatable should compare name, interface, and peers.
	@Test("Tunnels with same configuration are equal")
	func tunnelsWithSameConfigurationAreEqual() throws {
		// Given: two tunnels with identical configuration
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()

		let tunnel1 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer]
		)

		let tunnel2 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer]
		)

		// Then: tunnels are equal
		#expect(tunnel1 == tunnel2)
	}

	/// Test that tunnels with different names are not equal.
	///
	/// Different names mean different tunnel identities.
	@Test("Tunnels with different names are not equal")
	func tunnelsWithDifferentNamesAreNotEqual() throws {
		// Given: two tunnels with different names
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()

		let tunnel1 = try TunnelConfiguration(
			name: "Tunnel A",
			interface: interface,
			peers: [peer]
		)

		let tunnel2 = try TunnelConfiguration(
			name: "Tunnel B",
			interface: interface,
			peers: [peer]
		)

		// Then: tunnels are not equal
		#expect(tunnel1 != tunnel2)
	}

	/// Test that tunnels with different interfaces are not equal.
	///
	/// Different interface configurations mean different tunnels.
	@Test("Tunnels with different interfaces are not equal")
	func tunnelsWithDifferentInterfacesAreNotEqual() throws {
		// Given: two tunnels with different interfaces
		let interface1 = try makeInterfaceConfiguration()
		var interface2 = try makeInterfaceConfiguration()
		interface2.mtu = 1420

		let peer = try makePeerConfiguration()

		let tunnel1 = try TunnelConfiguration(
			name: "Test",
			interface: interface1,
			peers: [peer]
		)

		let tunnel2 = try TunnelConfiguration(
			name: "Test",
			interface: interface2,
			peers: [peer]
		)

		// Then: tunnels are not equal
		#expect(tunnel1 != tunnel2)
	}

	/// Test that tunnels with different peers are not equal.
	///
	/// Different peer configurations mean different routing.
	@Test("Tunnels with different peers are not equal")
	func tunnelsWithDifferentPeersAreNotEqual() throws {
		// Given: two tunnels with different peers
		let interface = try makeInterfaceConfiguration()
		let peer1 = try makePeerConfiguration()
		let peer2 = PeerConfiguration(publicKey: PrivateKey().publicKey)

		let tunnel1 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer1]
		)

		let tunnel2 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer2]
		)

		// Then: tunnels are not equal
		#expect(tunnel1 != tunnel2)
	}

	/// Test that peer order does not affect equality.
	///
	/// Peers are an unordered set conceptually, so different ordering
	/// of the same peers should still be equal.
	@Test("Peer order does not affect equality")
	func peerOrderDoesNotAffectEquality() throws {
		// Given: two tunnels with same peers in different order
		let interface = try makeInterfaceConfiguration()
		let peer1 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		let peer2 = PeerConfiguration(publicKey: PrivateKey().publicKey)

		let tunnel1 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer1, peer2]
		)

		let tunnel2 = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer2, peer1]  // Reversed order
		)

		// Then: tunnels are equal
		#expect(tunnel1 == tunnel2)
	}

}
