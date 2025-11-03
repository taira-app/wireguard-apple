import Foundation
import Network

/// A WireGuard endpoint representing a peer's network address.
///
/// An endpoint consists of a host (hostname or IP address) and a port number.
/// Endpoints are used to specify where to send encrypted packets for a peer.
///
/// ## String format
///
/// Endpoints are typically represented as "host:port":
///
/// ```swift
/// // IPv4 endpoint
/// let endpoint = Endpoint(from: "192.168.1.1:51820")
///
/// // IPv6 endpoint (requires bracket notation)
/// let endpoint = Endpoint(from: "[2001:db8::1]:51820")
///
/// // Hostname endpoint
/// let endpoint = Endpoint(from: "vpn.example.com:51820")
/// ```
///
/// ## Thread safety
///
/// This type is thread-safe and conforms to `Sendable` for use in concurrent contexts.
public struct Endpoint: Sendable, Equatable, Hashable {
	/// The host component of the endpoint.
	///
	/// This can be a hostname, IPv4 address, or IPv6 address.
	public enum Host: Sendable, Equatable, Hashable {
		/// A DNS hostname.
		case name(String)

		/// An IPv4 address.
		case ipv4(IPv4Address)

		/// An IPv6 address.
		case ipv6(IPv6Address)

		/// The string representation of the host.
		public var stringRepresentation: String {
			switch self {
			case .name(let hostname):
				return hostname
			case .ipv4(let address):
				return address.debugDescription
			case .ipv6(let address):
				return address.debugDescription
			}
		}
	}

	/// The host component (hostname or IP address).
	public let host: Host

	/// The port number (1-65535).
	public let port: UInt16

	/// Creates an endpoint with the specified host and port.
	///
	/// - Parameters:
	///   - host: The host component (hostname or IP address).
	///   - port: The port number (1-65535).
	public init(host: Host, port: UInt16) {
		self.host = host
		self.port = port
	}

	/// Creates an endpoint by parsing a string.
	///
	/// The string must be in the format "host:port". For IPv6 addresses,
	/// use bracket notation: "[2001:db8::1]:51820".
	///
	/// - Parameter string: The endpoint string to parse.
	/// - Returns: An endpoint instance, or `nil` if the string is invalid.
	public init?(from string: String) {
		// Check for IPv6 bracket notation [address]:port
		if string.hasPrefix("[") {
			guard let closeBracket = string.firstIndex(of: "]") else {
				return nil
			}

			let addressStart = string.index(after: string.startIndex)
			let addressString = String(string[addressStart..<closeBracket])

			// Parse the IPv6 address
			guard let ipv6Address = IPv6Address(addressString) else {
				return nil
			}

			// Parse the port after the closing bracket
			let afterBracket = string.index(after: closeBracket)
			guard afterBracket < string.endIndex,
				string[afterBracket] == ":"
			else {
				return nil
			}

			let portStart = string.index(after: afterBracket)
			let portString = String(string[portStart...])

			guard let portValue = UInt16(portString), portValue > 0 else {
				return nil
			}

			self.host = .ipv6(ipv6Address)
			self.port = portValue
			return
		}

		// Standard host:port format
		let components = string.split(separator: ":", maxSplits: 1)
		guard components.count == 2 else {
			return nil
		}

		let hostString = String(components[0])
		let portString = String(components[1])

		// Parse port
		guard let portValue = UInt16(portString), portValue > 0 else {
			return nil
		}

		// Try to parse as IPv4 first
		if let ipv4Address = IPv4Address(hostString) {
			self.host = .ipv4(ipv4Address)
			self.port = portValue
			return
		}

		// Try to parse as IPv6 (without brackets)
		if let ipv6Address = IPv6Address(hostString) {
			self.host = .ipv6(ipv6Address)
			self.port = portValue
			return
		}

		// Treat as hostname
		self.host = .name(hostString)
		self.port = portValue
	}

	/// The string representation of the endpoint.
	///
	/// IPv6 addresses are enclosed in brackets: "[2001:db8::1]:51820"
	public var stringRepresentation: String {
		switch host {
		case .name(let hostname):
			return "\(hostname):\(port)"
		case .ipv4(let address):
			return "\(address.debugDescription):\(port)"
		case .ipv6(let address):
			return "[\(address.debugDescription)]:\(port)"
		}
	}
}
