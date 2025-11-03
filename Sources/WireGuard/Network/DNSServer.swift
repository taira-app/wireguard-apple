import Foundation
import Network

/// A DNS server address for a WireGuard interface.
///
/// DNS servers are configured on a WireGuard interface to specify which DNS resolvers
/// should be used when the tunnel is active. Both IPv4 and IPv6 DNS servers are supported.
///
/// ## Usage
///
/// DNS servers can be created from IP address strings:
///
/// ```swift
/// // IPv4 DNS server
/// let dns1 = DNSServer(from: "8.8.8.8")
///
/// // IPv6 DNS server
/// let dns2 = DNSServer(from: "2001:4860:4860::8888")
/// ```
///
/// ## Thread safety
///
/// This type is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public struct DNSServer: Sendable, Equatable, Hashable {
	/// The DNS server address.
	public enum Address: Sendable, Equatable, Hashable {
		/// An IPv4 DNS server address.
		case ipv4(IPv4Address)

		/// An IPv6 DNS server address.
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

	/// The DNS server IP address.
	public let address: Address

	/// Creates a DNS server with the specified address.
	///
	/// - Parameter address: The DNS server IP address.
	public init(address: Address) {
		self.address = address
	}

	/// Creates a DNS server by parsing an IP address string.
	///
	/// The string must be a valid IPv4 or IPv6 address.
	///
	/// - Parameter string: The IP address string to parse.
	/// - Returns: A DNS server instance, or `nil` if the string is invalid.
	public init?(from string: String) {
		// Try to parse as IPv4
		if let ipv4Address = IPv4Address(string) {
			self.address = .ipv4(ipv4Address)
			return
		}

		// Try to parse as IPv6
		if let ipv6Address = IPv6Address(string) {
			self.address = .ipv6(ipv6Address)
			return
		}

		// Could not parse as either IPv4 or IPv6
		return nil
	}

	/// The string representation of the DNS server address.
	public var stringRepresentation: String {
		address.stringRepresentation
	}
}
