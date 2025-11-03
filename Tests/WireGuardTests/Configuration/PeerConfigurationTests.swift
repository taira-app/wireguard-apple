// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for the PeerConfiguration struct.
///
/// These tests verify peer configuration creation, validation, and field management.
/// They ensure that peer configurations properly handle required fields, optional fields,
/// statistics, and the special equality/hashing semantics.
@Suite("Peer configuration tests")
struct PeerConfigurationTests {

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

	// MARK: - Initialization tests

	/// Test that PeerConfiguration can be initialized with just a public key.
	///
	/// The minimum valid peer configuration requires only a public key, which
	/// serves as the peer's cryptographic identity.
	@Test("Peer configuration can be initialized with public key")
	func initializeWithPublicKey() throws {
		// Given: a public key
		let publicKey = makePublicKey()

		// When: creating a peer configuration
		let peer = PeerConfiguration(publicKey: publicKey)

		// Then: configuration is created with the public key
		#expect(peer.publicKey == publicKey)
	}

	/// Test that newly initialized peer has empty allowed IPs.
	///
	/// By default, the allowed IPs array should be empty and ready for population.
	@Test("New peer configuration has empty allowed IPs")
	func newPeerHasEmptyAllowedIPs() throws {
		// Given: a new peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// Then: allowed IPs array is empty
		#expect(peer.allowedIPs.isEmpty)
	}

	/// Test that newly initialized peer has no preshared key.
	///
	/// Preshared key is optional and should be nil by default.
	@Test("New peer configuration has no preshared key")
	func newPeerHasNoPresharedKey() throws {
		// Given: a new peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// Then: preshared key is nil
		#expect(peer.presharedKey == nil)
	}

	/// Test that newly initialized peer has no endpoint.
	///
	/// Endpoint is optional and should be nil by default (server peers or
	/// peers discovered through roaming).
	@Test("New peer configuration has no endpoint")
	func newPeerHasNoEndpoint() throws {
		// Given: a new peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// Then: endpoint is nil
		#expect(peer.endpoint == nil)
	}

	/// Test that newly initialized peer has no persistent keepalive.
	///
	/// Persistent keepalive is optional and should be nil by default.
	@Test("New peer configuration has no persistent keepalive")
	func newPeerHasNoPersistentKeepalive() throws {
		// Given: a new peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// Then: persistent keepalive is nil
		#expect(peer.persistentKeepalive == nil)
	}

	/// Test that newly initialized peer has no statistics.
	///
	/// Statistics fields should all be nil by default (no data yet).
	@Test("New peer configuration has no statistics")
	func newPeerHasNoStatistics() throws {
		// Given: a new peer configuration
		let peer = PeerConfiguration(publicKey: makePublicKey())

		// Then: all statistics are nil
		#expect(peer.receivedBytes == nil)
		#expect(peer.transmittedBytes == nil)
		#expect(peer.lastHandshakeTime == nil)
	}

	// MARK: - Allowed IPs tests

	/// Test that allowed IPs can be added to the peer.
	///
	/// Allowed IPs define which traffic should be routed to this peer.
	@Test("Allowed IPs can be added to peer")
	func addAllowedIPs() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: adding allowed IPs
		let ipv4 = try makeIPv4AddressRange()
		let ipv6 = try makeIPv6AddressRange()
		peer.allowedIPs = [ipv4, ipv6]

		// Then: allowed IPs are stored
		#expect(peer.allowedIPs.count == 2)
		#expect(peer.allowedIPs.contains(ipv4))
		#expect(peer.allowedIPs.contains(ipv6))
	}

	/// Test that peer can have full-tunnel routing (0.0.0.0/0).
	///
	/// Full-tunnel configuration routes all IPv4 traffic through this peer.
	@Test("Peer can have full-tunnel IPv4 routing")
	func fullTunnelIPv4Routing() throws {
		// Given: a peer with full-tunnel IPv4 allowed IP
		var peer = PeerConfiguration(publicKey: makePublicKey())
		let fullTunnel = try #require(IPAddressRange(from: "0.0.0.0/0"))
		peer.allowedIPs = [fullTunnel]

		// Then: peer routes all IPv4 traffic
		#expect(peer.allowedIPs.count == 1)
		#expect(peer.allowedIPs.first == fullTunnel)
	}

	/// Test that peer can have split-tunnel routing.
	///
	/// Split-tunnel configuration routes only specific subnets through the peer.
	@Test("Peer can have split-tunnel routing")
	func splitTunnelRouting() throws {
		// Given: a peer with specific subnet routing
		var peer = PeerConfiguration(publicKey: makePublicKey())
		peer.allowedIPs = [
			try #require(IPAddressRange(from: "10.0.0.0/24")),
			try #require(IPAddressRange(from: "192.168.1.0/24"))
		]

		// Then: peer routes only specified subnets
		#expect(peer.allowedIPs.count == 2)
	}

	// MARK: - Optional field tests

	/// Test that preshared key can be set.
	///
	/// Preshared keys provide additional post-quantum security.
	@Test("Preshared key can be set")
	func setPresharedKey() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting preshared key
		let psk = makePresharedKey()
		peer.presharedKey = psk

		// Then: preshared key is stored
		#expect(peer.presharedKey == psk)
	}

	/// Test that endpoint can be set.
	///
	/// Endpoints specify where to send encrypted packets for this peer.
	@Test("Endpoint can be set")
	func setEndpoint() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting endpoint
		let endpoint = try makeEndpoint()
		peer.endpoint = endpoint

		// Then: endpoint is stored
		#expect(peer.endpoint == endpoint)
	}

	/// Test that persistent keepalive can be set.
	///
	/// Persistent keepalive maintains NAT mappings for peers behind NAT.
	@Test("Persistent keepalive can be set")
	func setPersistentKeepalive() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting persistent keepalive
		peer.persistentKeepalive = 25

		// Then: keepalive is stored
		#expect(peer.persistentKeepalive == 25)
	}

	/// Test that persistent keepalive can be disabled.
	///
	/// Setting keepalive to 0 or nil disables it.
	@Test("Persistent keepalive can be disabled")
	func disablePersistentKeepalive() throws {
		// Given: a peer with keepalive enabled
		var peer = PeerConfiguration(publicKey: makePublicKey())
		peer.persistentKeepalive = 25

		// When: disabling keepalive
		peer.persistentKeepalive = nil

		// Then: keepalive is nil
		#expect(peer.persistentKeepalive == nil)
	}

	// MARK: - Statistics field tests

	/// Test that received bytes can be set.
	///
	/// Received bytes tracks total data received from this peer.
	@Test("Received bytes can be set")
	func setReceivedBytes() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting received bytes
		peer.receivedBytes = 1024

		// Then: received bytes is stored
		#expect(peer.receivedBytes == 1024)
	}

	/// Test that transmitted bytes can be set.
	///
	/// Transmitted bytes tracks total data sent to this peer.
	@Test("Transmitted bytes can be set")
	func setTransmittedBytes() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting transmitted bytes
		peer.transmittedBytes = 2048

		// Then: transmitted bytes is stored
		#expect(peer.transmittedBytes == 2048)
	}

	/// Test that last handshake time can be set.
	///
	/// Last handshake time tracks when the last successful handshake occurred.
	@Test("Last handshake time can be set")
	func setLastHandshakeTime() throws {
		// Given: a peer configuration
		var peer = PeerConfiguration(publicKey: makePublicKey())

		// When: setting last handshake time
		let now = Date()
		peer.lastHandshakeTime = now

		// Then: last handshake time is stored
		#expect(peer.lastHandshakeTime == now)
	}

}
