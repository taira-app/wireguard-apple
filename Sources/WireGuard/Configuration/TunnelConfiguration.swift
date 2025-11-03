// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Complete configuration for a WireGuard tunnel.
///
/// A tunnel configuration combines an interface configuration (the local side)
/// with one or more peer configurations (the remote sides) to define a complete
/// WireGuard VPN tunnel.
///
/// This corresponds to a complete WireGuard configuration file with `[Interface]`
/// and one or more `[Peer]` sections. The configuration is validated at creation
/// time to ensure it meets WireGuard protocol requirements.
///
/// ## Configuration requirements
///
/// A valid tunnel configuration must satisfy:
/// - At least one peer is configured
/// - All peer public keys are unique (no duplicates)
/// - Interface has valid settings (separate validation)
///
/// These requirements are enforced by the initializer, which throws
/// `ConfigurationError` if validation fails.
///
/// ## Usage
///
/// Creating a client tunnel configuration:
///
/// ```swift
/// // Configure interface
/// var interface = InterfaceConfiguration(privateKey: clientPrivateKey)
/// interface.addresses = [IPAddressRange(from: "10.0.0.2/24")!]
/// interface.dns = [DNSServer(from: "1.1.1.1")!]
///
/// // Configure peer (server)
/// var peer = PeerConfiguration(publicKey: serverPublicKey)
/// peer.endpoint = Endpoint(from: "vpn.example.com:51820")!
/// peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]
/// peer.persistentKeepalive = 25
///
/// // Create tunnel
/// let tunnel = try TunnelConfiguration(
///     name: "My VPN",
///     interface: interface,
///     peers: [peer]
/// )
/// ```
///
/// Creating a server tunnel configuration:
///
/// ```swift
/// // Configure interface
/// var interface = InterfaceConfiguration(privateKey: serverPrivateKey)
/// interface.addresses = [IPAddressRange(from: "10.0.0.1/24")!]
/// interface.listenPort = 51820
///
/// // Configure peers (clients)
/// var client1 = PeerConfiguration(publicKey: client1PublicKey)
/// client1.allowedIPs = [IPAddressRange(from: "10.0.0.2/32")!]
///
/// var client2 = PeerConfiguration(publicKey: client2PublicKey)
/// client2.allowedIPs = [IPAddressRange(from: "10.0.0.3/32")!]
///
/// // Create tunnel
/// let tunnel = try TunnelConfiguration(
///     name: "VPN Server",
///     interface: interface,
///     peers: [client1, client2]
/// )
/// ```
///
/// ## Immutability design
///
/// The peers array is immutable (`let`) after creation to ensure configuration
/// stability. Once a tunnel is created with a set of peers, those peers cannot
/// be added, removed, or reordered. To change peers, create a new tunnel configuration.
///
/// The interface configuration and tunnel name remain mutable (`var`) as these
/// can be safely modified without affecting the fundamental tunnel structure.
///
/// ## Thread safety
///
/// TunnelConfiguration is a value type (struct) and conforms to Sendable, making
/// it safe to pass across concurrency boundaries. Modifications create new copies
/// due to Swift's copy-on-write semantics.
public struct TunnelConfiguration: Sendable, Equatable {

	// MARK: - Properties

	/// Optional name for this tunnel.
	///
	/// The tunnel name is a human-readable identifier used for display purposes
	/// in user interfaces and logs. It has no effect on the tunnel's operation.
	///
	/// Examples:
	/// - `"My VPN"` - Simple descriptive name
	/// - `"Company Network"` - Corporate VPN
	/// - `nil` - Unnamed tunnel
	///
	/// When `nil`, applications may generate a display name from other properties
	/// like the first peer's endpoint hostname.
	public var name: String?

	/// The interface configuration for the local side of the tunnel.
	///
	/// The interface configuration defines:
	/// - Private key (local identity)
	/// - IP addresses assigned to the tunnel interface
	/// - DNS servers and search domains
	/// - Optional listen port (for servers)
	/// - Optional MTU setting
	///
	/// This configuration is mutable and can be updated after tunnel creation,
	/// though changes typically require recreating the actual tunnel connection.
	public var interface: InterfaceConfiguration

	/// The peer configurations for remote endpoints.
	///
	/// Each peer represents a remote endpoint that this tunnel can communicate with.
	/// A tunnel must have at least one peer to be valid.
	///
	/// The peers array is immutable after creation to ensure configuration stability.
	/// To add or remove peers, create a new TunnelConfiguration.
	///
	/// Peers are identified uniquely by their public keys. Attempting to create
	/// a configuration with duplicate peer public keys will fail validation.
	public let peers: [PeerConfiguration]

	// MARK: - Initialization

	/// Creates a new tunnel configuration with validation.
	///
	/// This initializer creates a complete tunnel configuration and validates
	/// that it meets WireGuard protocol requirements:
	/// - At least one peer must be provided
	/// - All peer public keys must be unique
	///
	/// If validation fails, a `ConfigurationError` is thrown describing the
	/// specific issue.
	///
	/// ## Example
	///
	/// ```swift
	/// let tunnel = try TunnelConfiguration(
	///     name: "My VPN",
	///     interface: interface,
	///     peers: [peer1, peer2]
	/// )
	/// ```
	///
	/// - Parameters:
	///   - name: Optional human-readable name for the tunnel
	///   - interface: Interface configuration for the local side
	///   - peers: Array of one or more peer configurations
	///
	/// - Throws:
	///   - `ConfigurationError.noPeers` if the peers array is empty
	///   - `ConfigurationError.duplicatePeerPublicKey` if multiple peers share
	///     the same public key
	public init(
		name: String?,
		interface: InterfaceConfiguration,
		peers: [PeerConfiguration]
	) throws {
		// Validate that at least one peer is provided
		guard !peers.isEmpty else {
			throw ConfigurationError.noPeers
		}

		// Validate that all peer public keys are unique
		var seenPublicKeys = Set<PublicKey>()
		for peer in peers {
			if seenPublicKeys.contains(peer.publicKey) {
				// Found a duplicate public key
				throw ConfigurationError.duplicatePeerPublicKey(
					publicKey: peer.publicKey.base64Key
				)
			}
			seenPublicKeys.insert(peer.publicKey)
		}

		// All validation passed, initialize the configuration
		self.name = name
		self.interface = interface
		self.peers = peers
	}

	// MARK: - Equatable conformance

	/// Compares two tunnel configurations for equality.
	///
	/// Two tunnel configurations are considered equal if all their properties
	/// have identical values:
	/// - Same name (or both nil)
	/// - Same interface configuration
	/// - Same set of peers (order-independent)
	///
	/// The order of peers does not affect equality because peers are conceptually
	/// an unordered set, each identified uniquely by their public key.
	///
	/// Peer statistics (receivedBytes, transmittedBytes, lastHandshakeTime) do
	/// not affect equality, as those are excluded from PeerConfiguration equality.
	///
	/// - Parameters:
	///   - lhs: The left-hand tunnel configuration
	///   - rhs: The right-hand tunnel configuration
	/// - Returns: `true` if both configurations have identical values
	public static func == (lhs: TunnelConfiguration, rhs: TunnelConfiguration) -> Bool {
		// Compare names
		guard lhs.name == rhs.name else {
			return false
		}

		// Compare interface configurations
		guard lhs.interface == rhs.interface else {
			return false
		}

		// Compare peers (order-independent)
		// Since PeerConfiguration conforms to Hashable, we can use Set comparison
		guard Set(lhs.peers) == Set(rhs.peers) else {
			return false
		}

		return true
	}
}
