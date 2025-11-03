// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Configuration for a WireGuard peer.
///
/// A peer configuration defines a remote endpoint in the WireGuard tunnel,
/// including its cryptographic identity (public key), network location (endpoint),
/// routing rules (allowed IPs), and optional settings like preshared keys and
/// persistent keepalive.
///
/// This configuration corresponds to a `[Peer]` section in WireGuard configuration
/// files. A tunnel can have multiple peers, each identified uniquely by its public key.
///
/// ## Identity and equality
///
/// Peers are identified by their public key, which is immutable after creation.
/// Two peer configurations are considered equal if they have the same configuration
/// (excluding statistics), and hash identically if they have the same public key.
///
/// Statistics fields (receivedBytes, transmittedBytes, lastHandshakeTime) are
/// excluded from equality comparisons because they represent runtime state rather
/// than configuration.
///
/// ## Usage
///
/// Creating a basic client peer (connecting to server):
///
/// ```swift
/// let serverPublicKey = try PublicKey(base64Key: "...")
/// var peer = PeerConfiguration(publicKey: serverPublicKey)
/// peer.endpoint = Endpoint(from: "vpn.example.com:51820")!
/// peer.allowedIPs = [
///     IPAddressRange(from: "0.0.0.0/0")!,  // Route all IPv4 traffic
///     IPAddressRange(from: "::/0")!         // Route all IPv6 traffic
/// ]
/// peer.persistentKeepalive = 25  // Keep NAT mapping alive
/// ```
///
/// Creating a server peer (accepting connections):
///
/// ```swift
/// let clientPublicKey = try PublicKey(base64Key: "...")
/// var peer = PeerConfiguration(publicKey: clientPublicKey)
/// peer.allowedIPs = [
///     IPAddressRange(from: "10.0.0.2/32")!  // Only route this client's IP
/// ]
/// // No endpoint - server learns it from incoming packets
/// ```
///
/// ## Thread safety
///
/// PeerConfiguration is a value type (struct) and conforms to Sendable, making
/// it safe to pass across concurrency boundaries. Modifications create new copies
/// due to Swift's copy-on-write semantics.
public struct PeerConfiguration: Sendable, Equatable, Hashable {

	// MARK: - Identity

	/// The public key of this peer.
	///
	/// This is the cryptographic identity of the peer and is immutable after
	/// creation. The public key must match the private key the peer uses, and
	/// serves as the unique identifier for this peer in the tunnel.
	///
	/// Each peer in a tunnel must have a unique public key. Attempting to add
	/// multiple peers with the same public key will result in a configuration error.
	public let publicKey: PublicKey

	// MARK: - Security

	/// Optional preshared key for additional security.
	///
	/// A preshared key adds an additional layer of symmetric encryption to the
	/// WireGuard tunnel, providing post-quantum security. Both peers must be
	/// configured with the same preshared key for it to work.
	///
	/// When set to `nil`, only the public key cryptography is used (standard
	/// WireGuard). This is secure but theoretically vulnerable to future quantum
	/// computers.
	///
	/// Best practices:
	/// - Generate with `PresharedKey()` for cryptographically secure random keys
	/// - Share securely out-of-band (don't transmit over the tunnel)
	/// - Rotate periodically for maximum security
	public var presharedKey: PresharedKey?

	// MARK: - Routing

	/// The IP address ranges that should be routed to this peer.
	///
	/// Allowed IPs define which destination addresses will be encrypted and
	/// sent to this peer. This is the cryptokey routing table for WireGuard.
	///
	/// Examples:
	/// - `["0.0.0.0/0", "::/0"]` - Full tunnel (route all traffic)
	/// - `["10.0.0.0/24"]` - Split tunnel (route only this subnet)
	/// - `["10.0.0.2/32"]` - Single host (route only this IP)
	///
	/// Multiple ranges can be specified for complex routing scenarios. When
	/// multiple peers have overlapping allowed IPs, the most specific match wins.
	///
	/// An empty array means no traffic will be routed to this peer.
	public var allowedIPs: [IPAddressRange]

	// MARK: - Network location

	/// The network endpoint where this peer can be reached.
	///
	/// The endpoint specifies the IP address (or hostname) and UDP port where
	/// encrypted packets should be sent for this peer.
	///
	/// Examples:
	/// - `"vpn.example.com:51820"` - Hostname with port
	/// - `"203.0.113.1:51820"` - IPv4 address with port
	/// - `"[2001:db8::1]:51820"` - IPv6 address with port
	///
	/// When set to `nil`:
	/// - For servers: The endpoint is learned from incoming packets (roaming)
	/// - For clients: The peer cannot be reached until endpoint is set
	///
	/// WireGuard supports roaming, so the endpoint can change if packets are
	/// received from a different source address. This is useful for mobile clients.
	public var endpoint: Endpoint?

	// MARK: - Keepalive

	/// Persistent keepalive interval in seconds.
	///
	/// When set, WireGuard will send an authenticated keepalive packet to this
	/// peer every N seconds, even when no data is being transmitted. This helps:
	/// - Maintain NAT mappings through firewalls
	/// - Keep the tunnel responsive for immediate data transmission
	/// - Prevent the peer from appearing offline
	///
	/// Valid values:
	/// - `nil` - No keepalive (default for servers with static IPs)
	/// - `1-65535` - Keepalive interval in seconds
	/// - `25` - Common value for clients behind NAT
	///
	/// Setting this too low wastes bandwidth and battery. Setting it too high
	/// may cause NAT mappings to expire. Most NAT timeouts are 30-60 seconds,
	/// so 25 seconds provides good margin.
	///
	/// Servers typically don't need keepalive as they respond to client packets.
	/// Clients behind NAT should set this to maintain the connection.
	public var persistentKeepalive: UInt16?

	// MARK: - Runtime statistics

	/// Total number of bytes received from this peer.
	///
	/// This field tracks cumulative data received from the peer since the tunnel
	/// started. It's set by the tunnel engine during operation and should not
	/// be manually modified in configuration.
	///
	/// This field is excluded from equality comparisons as it represents runtime
	/// state rather than configuration.
	public var receivedBytes: UInt64?

	/// Total number of bytes transmitted to this peer.
	///
	/// This field tracks cumulative data sent to the peer since the tunnel
	/// started. It's set by the tunnel engine during operation and should not
	/// be manually modified in configuration.
	///
	/// This field is excluded from equality comparisons as it represents runtime
	/// state rather than configuration.
	public var transmittedBytes: UInt64?

	/// Timestamp of the last successful handshake with this peer.
	///
	/// WireGuard performs a handshake every few minutes to rotate session keys.
	/// This timestamp indicates when the most recent handshake completed successfully.
	///
	/// A recent handshake time (within the last few minutes) indicates the peer
	/// is actively connected. An old or nil timestamp suggests the peer may be
	/// offline or unreachable.
	///
	/// This field is set by the tunnel engine and should not be manually modified
	/// in configuration. It's excluded from equality comparisons as it represents
	/// runtime state.
	public var lastHandshakeTime: Date?

	// MARK: - Initialization

	/// Creates a new peer configuration with the specified public key.
	///
	/// This initializer creates a minimal peer configuration with only the
	/// required public key. All other fields are initialized to empty or nil
	/// and should be configured after initialization.
	///
	/// ## Example
	///
	/// ```swift
	/// let publicKey = try PublicKey(base64Key: "...")
	/// var peer = PeerConfiguration(publicKey: publicKey)
	/// peer.allowedIPs = [IPAddressRange(from: "10.0.0.0/24")!]
	/// peer.endpoint = Endpoint(from: "vpn.example.com:51820")!
	/// ```
	///
	/// - Parameter publicKey: The public key for this peer. This is the
	///   cryptographic identity of the peer and cannot be changed after creation.
	public init(publicKey: PublicKey) {
		self.publicKey = publicKey
		self.presharedKey = nil
		self.allowedIPs = []
		self.endpoint = nil
		self.persistentKeepalive = nil
		self.receivedBytes = nil
		self.transmittedBytes = nil
		self.lastHandshakeTime = nil
	}

	// MARK: - Equatable conformance

	/// Compares two peer configurations for equality.
	///
	/// Two peer configurations are considered equal if all their configuration
	/// fields have identical values. Configuration fields include:
	/// - Public key
	/// - Preshared key
	/// - Allowed IPs (order-independent)
	/// - Endpoint
	/// - Persistent keepalive
	///
	/// Statistics fields (receivedBytes, transmittedBytes, lastHandshakeTime)
	/// are deliberately excluded from comparison because they represent runtime
	/// state rather than configuration. Two peers with the same configuration but
	/// different statistics are considered equal.
	///
	/// This allows configurations to be compared for equivalence while ignoring
	/// transient runtime data.
	///
	/// - Parameters:
	///   - lhs: The left-hand peer configuration
	///   - rhs: The right-hand peer configuration
	/// - Returns: `true` if both configurations have identical settings
	public static func == (lhs: PeerConfiguration, rhs: PeerConfiguration) -> Bool {
		// Compare public key (peer identity)
		guard lhs.publicKey == rhs.publicKey else {
			return false
		}

		// Compare preshared key
		guard lhs.presharedKey == rhs.presharedKey else {
			return false
		}

		// Compare allowed IPs (order-independent)
		guard Set(lhs.allowedIPs) == Set(rhs.allowedIPs) else {
			return false
		}

		// Compare endpoint
		guard lhs.endpoint == rhs.endpoint else {
			return false
		}

		// Compare persistent keepalive
		guard lhs.persistentKeepalive == rhs.persistentKeepalive else {
			return false
		}

		// Statistics are intentionally not compared
		return true
	}

	// MARK: - Hashable conformance

	/// Computes the hash value based solely on the public key.
	///
	/// The hash value is computed using only the public key, which is the
	/// unique identifier for the peer. This means:
	/// - Peers with the same public key hash identically
	/// - Peers can be efficiently stored in Sets and Dictionaries
	/// - Changing other fields doesn't affect the hash
	///
	/// This design allows peers to be looked up by public key in collections
	/// while still allowing their configuration to be modified.
	///
	/// - Parameter hasher: The hasher to use for combining hash values
	public func hash(into hasher: inout Hasher) {
		// Hash only the public key (peer identity)
		hasher.combine(publicKey)
		// Other fields deliberately not hashed to maintain hash stability
	}
}
