// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for real-world TunnelConfiguration scenarios.
///
/// These tests verify complete tunnel configurations for common use cases
/// like VPN clients, servers, site-to-site connections, and mobile scenarios.
@Suite("Real-world tunnel configuration tests")
struct TunnelConfigurationRealWorldTests {

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

	// MARK: - Real-world configuration tests

	/// Test a typical client VPN configuration.
	///
	/// Validates a common client setup with full tunnel routing.
	@Test("Typical client VPN configuration")
	func typicalClientVPNConfiguration() throws {
		// Given: a client configuration
		var interface = InterfaceConfiguration(privateKey: PrivateKey())
		interface.addresses = [
			try #require(IPAddressRange(from: "10.0.0.2/24"))
		]
		interface.dns = [
			try #require(DNSServer(from: "1.1.1.1"))
		]

		var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
		peer.endpoint = try #require(Endpoint(from: "vpn.example.com:51820"))
		peer.allowedIPs = [
			try #require(IPAddressRange(from: "0.0.0.0/0"))  // Full tunnel
		]
		peer.persistentKeepalive = 25

		// When: creating the tunnel
		let tunnel = try TunnelConfiguration(
			name: "My VPN",
			interface: interface,
			peers: [peer]
		)

		// Then: tunnel is valid
		#expect(tunnel.peers.count == 1)
		#expect(tunnel.interface.dns.count == 1)
	}

	/// Test a typical server configuration with multiple clients.
	///
	/// Validates a server setup accepting connections from multiple clients.
	@Test("Typical server configuration")
	func typicalServerConfiguration() throws {
		// Given: a server configuration
		var interface = InterfaceConfiguration(privateKey: PrivateKey())
		interface.addresses = [
			try #require(IPAddressRange(from: "10.0.0.1/24"))
		]
		interface.listenPort = 51820

		// Multiple client peers
		var client1 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		client1.allowedIPs = [try #require(IPAddressRange(from: "10.0.0.2/32"))]

		var client2 = PeerConfiguration(publicKey: PrivateKey().publicKey)
		client2.allowedIPs = [try #require(IPAddressRange(from: "10.0.0.3/32"))]

		// When: creating the tunnel
		let tunnel = try TunnelConfiguration(
			name: "VPN Server",
			interface: interface,
			peers: [client1, client2]
		)

		// Then: tunnel is valid
		#expect(tunnel.peers.count == 2)
		#expect(tunnel.interface.listenPort == 51820)
	}

	// MARK: - Sendable conformance test

	/// Test that TunnelConfiguration conforms to Sendable.
	///
	/// Sendable conformance is required for Swift 6 concurrency.
	@Test("TunnelConfiguration conforms to Sendable")
	func conformsToSendable() throws {
		// Given: a tunnel configuration
		let interface = try makeInterfaceConfiguration()
		let peer = try makePeerConfiguration()
		let tunnel = try TunnelConfiguration(
			name: "Test",
			interface: interface,
			peers: [peer]
		)

		// When: passing to an async context
		Task {
			// Then: tunnel can be sent across concurrency boundaries
			_ = tunnel
		}
	}
}
