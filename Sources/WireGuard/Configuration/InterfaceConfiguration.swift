// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Configuration for a WireGuard tunnel interface.
///
/// The interface configuration defines the local side of a WireGuard tunnel,
/// including the cryptographic identity (private key), IP address assignments,
/// DNS settings, and optional parameters like MTU and listen port.
///
/// This configuration corresponds to the `[Interface]` section in WireGuard
/// configuration files. It must be combined with at least one peer configuration
/// to create a complete tunnel configuration.
///
/// ## Usage
///
/// Creating a basic client interface configuration:
///
/// ```swift
/// let privateKey = PrivateKey()
/// var interface = InterfaceConfiguration(privateKey: privateKey)
/// interface.addresses = [
///     IPAddressRange(from: "10.0.0.2/24")!
/// ]
/// interface.dns = [
///     DNSServer(from: "1.1.1.1")!
/// ]
/// ```
///
/// Creating a server interface configuration with listen port:
///
/// ```swift
/// let privateKey = PrivateKey()
/// var interface = InterfaceConfiguration(privateKey: privateKey)
/// interface.addresses = [
///     IPAddressRange(from: "10.0.0.1/24")!
/// ]
/// interface.listenPort = 51820
/// ```
///
/// ## Thread safety
///
/// InterfaceConfiguration is a value type (struct) and conforms to Sendable,
/// making it safe to pass across concurrency boundaries. Modifications create
/// new copies due to Swift's copy-on-write semantics.
public struct InterfaceConfiguration: Sendable, Equatable {

	// MARK: - Required fields

	/// The private key for this interface.
	///
	/// This is the cryptographic identity of the local WireGuard interface.
	/// The corresponding public key is what peers will configure in their
	/// peer configurations to connect to this interface.
	///
	/// This field is required because a WireGuard interface cannot function
	/// without a private key for cryptographic operations.
	public var privateKey: PrivateKey

	// MARK: - Network addressing

	/// The IP address assignments for this interface in CIDR notation.
	///
	/// At least one address should be configured for the interface to route
	/// traffic. Multiple addresses are supported for dual-stack (IPv4 + IPv6)
	/// or multi-homed configurations.
	///
	/// Examples:
	/// - `["10.0.0.2/24"]` - Single IPv4 address
	/// - `["fd00::2/64"]` - Single IPv6 address
	/// - `["10.0.0.2/24", "fd00::2/64"]` - Dual-stack configuration
	///
	/// These addresses define what IP ranges the tunnel interface will handle.
	/// Traffic destined for these addresses will be routed to this interface.
	public var addresses: [IPAddressRange]

	// MARK: - DNS configuration

	/// DNS servers to use when the tunnel is active.
	///
	/// When specified, these DNS servers will be configured in the system's
	/// DNS resolver while the tunnel is active. This allows the tunnel to
	/// intercept and route DNS queries through the VPN.
	///
	/// Examples:
	/// - `["1.1.1.1", "1.0.0.1"]` - Cloudflare DNS
	/// - `["8.8.8.8", "8.8.4.4"]` - Google DNS
	/// - `["10.0.0.1"]` - Private DNS server through tunnel
	///
	/// An empty array means no DNS configuration changes.
	public var dns: [DNSServer]

	/// DNS search domains to use when the tunnel is active.
	///
	/// Search domains allow short hostname resolution by automatically
	/// appending these domains to unqualified hostnames.
	///
	/// For example, with a search domain of "internal.example.com",
	/// querying "server" would automatically try "server.internal.example.com".
	///
	/// An empty array means no search domains are configured.
	public var dnsSearch: [String]

	// MARK: - Optional server settings

	/// The UDP port to listen on for incoming connections.
	///
	/// This is typically only set for server-side configurations. When set,
	/// the WireGuard interface will listen on this port for incoming peer
	/// connections.
	///
	/// Common values:
	/// - `51820` - Default WireGuard port
	/// - `nil` - Client mode, no listening (default)
	///
	/// For client configurations, this should remain `nil` as clients
	/// typically use ephemeral ports and connect to servers, rather than
	/// listening for incoming connections.
	public var listenPort: UInt16?

	// MARK: - Performance tuning

	/// The maximum transmission unit (MTU) for the interface in bytes.
	///
	/// MTU determines the largest packet size that can be transmitted without
	/// fragmentation. WireGuard adds 60 bytes of overhead for IPv4 and 80 bytes
	/// for IPv6, so the tunnel MTU should be reduced accordingly.
	///
	/// Valid range: 1280-65535 bytes
	/// - Minimum 1280 ensures IPv6 compatibility (RFC 8200)
	/// - Maximum 65535 is the theoretical IP packet limit
	///
	/// Common values:
	/// - `1420` - Standard for Ethernet (1500 - 80 byte overhead)
	/// - `1280` - Conservative value ensuring no fragmentation
	/// - `nil` - Use system default (typically 1420)
	///
	/// Setting this too high can cause fragmentation; setting it too low
	/// reduces efficiency. When in doubt, use the default or 1420.
	public var mtu: UInt16?

	// MARK: - Initialization

	/// Creates a new interface configuration with the specified private key.
	///
	/// This initializer creates a minimal interface configuration with only
	/// the required private key. All other fields are initialized to empty
	/// or nil and should be configured after initialization.
	///
	/// ## Example
	///
	/// ```swift
	/// let privateKey = PrivateKey()
	/// var interface = InterfaceConfiguration(privateKey: privateKey)
	/// interface.addresses = [IPAddressRange(from: "10.0.0.2/24")!]
	/// ```
	///
	/// - Parameter privateKey: The private key for this interface. This is the
	///   cryptographic identity of the interface and is required for all
	///   WireGuard operations.
	public init(privateKey: PrivateKey) {
		self.privateKey = privateKey
		self.addresses = []
		self.dns = []
		self.dnsSearch = []
		self.listenPort = nil
		self.mtu = nil
	}

	// MARK: - Equatable conformance

	/// Compares two interface configurations for equality.
	///
	/// Two interface configurations are considered equal if all their fields
	/// have identical values. This includes:
	/// - Same private key
	/// - Same address assignments (order-independent)
	/// - Same DNS servers (order-independent)
	/// - Same DNS search domains (order-independent)
	/// - Same listen port
	/// - Same MTU
	///
	/// The order of addresses, DNS servers, and search domains does not affect
	/// equality, as these are unordered sets conceptually.
	///
	/// - Parameters:
	///   - lhs: The left-hand interface configuration
	///   - rhs: The right-hand interface configuration
	/// - Returns: `true` if both configurations have identical values
	public static func == (lhs: InterfaceConfiguration, rhs: InterfaceConfiguration) -> Bool {
		// Compare private key
		guard lhs.privateKey == rhs.privateKey else {
			return false
		}

		// Compare addresses (order-independent)
		guard Set(lhs.addresses) == Set(rhs.addresses) else {
			return false
		}

		// Compare DNS servers (order-independent)
		guard Set(lhs.dns) == Set(rhs.dns) else {
			return false
		}

		// Compare DNS search domains (order-independent)
		guard Set(lhs.dnsSearch) == Set(rhs.dnsSearch) else {
			return false
		}

		// Compare listen port
		guard lhs.listenPort == rhs.listenPort else {
			return false
		}

		// Compare MTU
		guard lhs.mtu == rhs.mtu else {
			return false
		}

		return true
	}
}
