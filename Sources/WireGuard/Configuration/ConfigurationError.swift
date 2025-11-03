// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Errors that can occur during tunnel configuration operations.
///
/// These errors cover validation failures when constructing or modifying
/// WireGuard tunnel configurations. They ensure that configurations meet
/// the requirements of the WireGuard protocol specification before being
/// used to establish tunnel connections.
///
/// Each error includes localized descriptions to help with debugging and
/// provides actionable recovery suggestions for fixing invalid configurations.
public enum ConfigurationError: Error, LocalizedError, Sendable, Equatable {
	/// No peers were provided in the tunnel configuration.
	///
	/// A valid WireGuard tunnel configuration must include at least one peer
	/// to establish a connection. A tunnel without peers cannot route any
	/// traffic and serves no purpose. This error is thrown when:
	/// - Creating a TunnelConfiguration with an empty peers array
	/// - Attempting to validate a configuration that has no peers
	///
	/// WireGuard requires at least one peer because the tunnel needs a
	/// destination for encrypted traffic. Even in a simple client-server
	/// setup, the client needs one peer (the server) configured.
	case noPeers

	/// Multiple peers share the same public key.
	///
	/// Each peer in a WireGuard configuration must have a unique public key.
	/// Public keys serve as the identity for peers, and duplicate keys would
	/// create ambiguity about which peer should receive traffic. This error
	/// occurs when:
	/// - Two or more PeerConfiguration instances have identical publicKey values
	/// - Adding a new peer whose public key already exists in the configuration
	///
	/// This validation ensures that the routing table can unambiguously map
	/// allowed IPs to specific peers. Duplicate keys would break the fundamental
	/// WireGuard security model.
	///
	/// - Parameter publicKey: The base64-encoded public key that appears in
	///   multiple peer configurations.
	case duplicatePeerPublicKey(publicKey: String)

	/// No interface addresses were provided in the interface configuration.
	///
	/// A valid interface configuration requires at least one IP address
	/// assignment in CIDR notation. The interface needs an address to:
	/// - Identify the local endpoint for routing
	/// - Enable the operating system to route packets through the tunnel
	/// - Establish the subnet for tunnel traffic
	///
	/// This error is thrown when:
	/// - Creating an InterfaceConfiguration with an empty addresses array
	/// - The addresses array is modified to become empty
	///
	/// Without an address, the tunnel interface cannot function because the
	/// operating system won't know what IP range the tunnel serves.
	case noAddresses

	/// The MTU (maximum transmission unit) value is outside the valid range.
	///
	/// MTU defines the largest packet size that can be transmitted through
	/// the tunnel without fragmentation. Valid MTU ranges are:
	/// - IPv4: 576 to 65535 bytes (minimum per RFC 791)
	/// - IPv6: 1280 to 65535 bytes (minimum per RFC 8200)
	///
	/// This error occurs when:
	/// - Setting an MTU below the minimum required value (1280 for modern tunnels)
	/// - Setting an MTU above the maximum value (65535)
	/// - Providing an MTU that would cause packet fragmentation issues
	///
	/// The minimum of 1280 bytes ensures IPv6 compatibility. Values below
	/// this can cause packet loss or connection failures with IPv6 traffic.
	///
	/// - Parameter mtu: The invalid MTU value that was provided.
	case invalidMTU(mtu: UInt16)

	/// The persistent keepalive interval is invalid.
	///
	/// Persistent keepalive sends periodic packets to maintain NAT mappings
	/// and firewall pinholes. The interval must be:
	/// - Between 1 and 65535 seconds for active keepalive
	/// - Set to 0 to disable keepalive entirely
	///
	/// This error occurs when:
	/// - Setting a keepalive interval to 0 when a non-zero value is required
	/// - Setting an interval that exceeds the maximum (65535 seconds)
	/// - Providing an interval that would be ineffective for the use case
	///
	/// Keepalive is typically set to 25 seconds for clients behind NAT, or
	/// disabled (0) for servers with stable endpoints. The maximum value of
	/// 65535 seconds (approximately 18 hours) is rarely practical.
	///
	/// - Parameter interval: The invalid keepalive interval that was provided.
	case invalidKeepalive(interval: UInt16)

	// MARK: - LocalizedError conformance

	/// A localized message describing what error occurred.
	public var errorDescription: String? {
		switch self {
		case .noPeers:
			return "Configuration must include at least one peer."
		case .duplicatePeerPublicKey(let publicKey):
			return "Duplicate peer public key: \(publicKey)"
		case .noAddresses:
			return "Interface configuration must include at least one address."
		case .invalidMTU(let mtu):
			return "Invalid MTU value: \(mtu)"
		case .invalidKeepalive(let interval):
			return "Invalid persistent keepalive interval: \(interval)"
		}
	}

	/// A localized message describing the reason for the failure.
	public var failureReason: String? {
		switch self {
		case .noPeers:
			return "WireGuard requires at least one peer to establish a tunnel connection. "
				+ "A tunnel without peers has no destination for traffic and cannot function."
		case .duplicatePeerPublicKey(let publicKey):
			return "The public key '\(publicKey)' appears in multiple peer configurations. "
				+ "Each peer must have a unique public key to avoid routing ambiguity."
		case .noAddresses:
			return "Interface requires at least one IP address in CIDR notation to enable "
				+ "packet routing through the tunnel."
		case .invalidMTU(let mtu):
			return "MTU value \(mtu) is outside the valid range. MTU must be between "
				+ "1280 and 65535 bytes to ensure IPv6 compatibility and avoid fragmentation."
		case .invalidKeepalive(let interval):
			return "Keepalive interval \(interval) is invalid. The interval must be "
				+ "between 1 and 65535 seconds, or set to 0 to disable keepalive."
		}
	}

	/// A localized message describing how to recover from the failure.
	public var recoverySuggestion: String? {
		switch self {
		case .noPeers:
			return "Add at least one peer configuration with a valid public key and "
				+ "allowed IP ranges. For a client configuration, add the server as a peer."
		case .duplicatePeerPublicKey:
			return "Ensure each peer has a unique public key. If you have duplicate entries, "
				+ "remove one of them. If you need to connect to multiple endpoints for the same peer, "
				+ "configure multiple allowed IPs or endpoints instead of duplicate peer entries."
		case .noAddresses:
			return "Add at least one IP address to the interface configuration using CIDR notation "
				+ "(e.g., '10.0.0.2/24' for IPv4 or '2001:db8::2/64' for IPv6)."
		case .invalidMTU:
			return "Set MTU to a value between 1280 and 65535 bytes. Recommended values are "
				+ "1420 for standard Ethernet or omit the MTU setting to use the system default (1420)."
		case .invalidKeepalive:
			return "Set persistent keepalive to a value between 1 and 65535 seconds. Common "
				+ "values are 25 seconds for clients behind NAT, or 0 to disable keepalive for "
				+ "servers with stable public endpoints."
		}
	}
}
