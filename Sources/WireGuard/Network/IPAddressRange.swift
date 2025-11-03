import Foundation
import Network

/// An IP address range in CIDR notation.
///
/// IP address ranges define subnets using an IP address and a network prefix length.
/// In WireGuard, these are used to specify which IP addresses should be routed through
/// the tunnel (allowed IPs) and which addresses the interface should use.
///
/// ## CIDR notation
///
/// CIDR notation consists of an IP address followed by a slash and prefix length:
///
/// ```swift
/// // IPv4 subnet
/// let range = IPAddressRange(from: "192.168.1.0/24")
///
/// // IPv6 subnet
/// let range = IPAddressRange(from: "2001:db8::/32")
///
/// // Single host (full prefix)
/// let ipv4Host = IPAddressRange(from: "192.168.1.1/32")
/// let ipv6Host = IPAddressRange(from: "2001:db8::1/128")
/// ```
///
/// ## Thread safety
///
/// This type is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public struct IPAddressRange: Sendable, Equatable, Hashable {
	/// The IP address component of the range.
	public enum Address: Sendable, Equatable, Hashable {
		/// An IPv4 address.
		case ipv4(IPv4Address)

		/// An IPv6 address.
		case ipv6(IPv6Address)

		/// The string representation of the address.
		public var stringRepresentation: String {
			switch self {
			case .ipv4(let address):
				return address.debugDescription
			case .ipv6(let address):
				return address.debugDescription
			}
		}

		/// Returns `true` if this is an IPv4 address.
		public var isIPv4: Bool {
			if case .ipv4 = self { return true }
			return false
		}

		/// Returns `true` if this is an IPv6 address.
		public var isIPv6: Bool {
			if case .ipv6 = self { return true }
			return false
		}
	}

	/// The IP address.
	public let address: Address

	/// The network prefix length in bits.
	///
	/// Valid range is 0-32 for IPv4 and 0-128 for IPv6.
	public let networkPrefixLength: UInt8

	/// The maximum prefix length for the address type.
	public var maxPrefixLength: UInt8 {
		switch address {
		case .ipv4:
			return 32
		case .ipv6:
			return 128
		}
	}

	/// Creates an IP address range with the specified address and prefix length.
	///
	/// - Parameters:
	///   - address: The IP address.
	///   - networkPrefixLength: The network prefix length (0-32 for IPv4, 0-128 for IPv6).
	/// - Returns: An IP address range, or `nil` if the prefix length is invalid.
	public init?(address: Address, networkPrefixLength: UInt8) {
		// Validate prefix length based on address type
		let maxPrefix: UInt8
		switch address {
		case .ipv4:
			maxPrefix = 32
		case .ipv6:
			maxPrefix = 128
		}

		guard networkPrefixLength <= maxPrefix else {
			return nil
		}

		self.address = address
		self.networkPrefixLength = networkPrefixLength
	}

	/// Creates an IP address range by parsing a CIDR notation string.
	///
	/// The string must be in the format "address/prefix" (e.g., "192.168.1.0/24").
	///
	/// - Parameter string: The CIDR notation string to parse.
	/// - Returns: An IP address range, or `nil` if the string is invalid.
	public init?(from string: String) {
		// Split on the slash
		let components = string.split(separator: "/", maxSplits: 1)
		guard components.count == 2 else {
			return nil
		}

		let addressString = String(components[0])
		let prefixString = String(components[1])

		// Parse prefix length
		guard let prefix = UInt8(prefixString) else {
			return nil
		}

		// Try to parse as IPv4
		if let ipv4Address = IPv4Address(addressString) {
			guard prefix <= 32 else {
				return nil
			}
			self.address = .ipv4(ipv4Address)
			self.networkPrefixLength = prefix
			return
		}

		// Try to parse as IPv6
		if let ipv6Address = IPv6Address(addressString) {
			guard prefix <= 128 else {
				return nil
			}
			self.address = .ipv6(ipv6Address)
			self.networkPrefixLength = prefix
			return
		}

		// Could not parse address
		return nil
	}

	/// The string representation in CIDR notation.
	///
	/// Format: "address/prefix" (e.g., "192.168.1.0/24")
	public var stringRepresentation: String {
		"\(address.stringRepresentation)/\(networkPrefixLength)"
	}

	/// Returns `true` if this represents a single host address.
	///
	/// A single host has a prefix length of 32 for IPv4 or 128 for IPv6.
	public var isSingleHost: Bool {
		networkPrefixLength == maxPrefixLength
	}

	/// Returns `true` if this represents all addresses (0.0.0.0/0 or ::/0).
	public var isAllAddresses: Bool {
		networkPrefixLength == 0
	}
}
