import Foundation
import Network
import NetworkExtension

/// Extension for generating IPv6 network settings.
///
/// This extension handles the conversion of IPv6 configuration from WireGuard format
/// to NetworkExtension format. It extracts IPv6 addresses from the interface configuration
/// and creates the appropriate NEIPv6Settings object.
extension TunnelSettingsGenerator {

	/// Generates IPv6 settings from the tunnel configuration.
	///
	/// This method examines the interface addresses and extracts IPv6 addresses.
	/// For each IPv6 address, it creates an NEIPv6Settings object with:
	/// - The IP address (e.g., "fd00::2")
	/// - The network prefix length (e.g., 64 for /64)
	/// - Routes generated from peer allowed IPs
	///
	/// If no IPv6 addresses are configured, this returns nil and no IPv6 settings
	/// will be applied to the tunnel.
	///
	/// - Returns: IPv6 settings if IPv6 addresses are configured, nil otherwise
	/// - Throws: `IntegrationError` if IPv6 routes cannot be generated
	func generateIPv6Settings() throws -> NEIPv6Settings? {
		// Extract IPv6 addresses from the interface configuration.
		let ipv6Addresses = configuration.interface.addresses.compactMap { range -> (String, NSNumber)? in
			// Check if this address is IPv6.
			switch range.address {
			case .ipv6(let ipv6Address):
				// Extract the address string.
				let addressString = ipv6Address.debugDescription

				// IPv6 uses network prefix lengths instead of subnet masks.
				// For example, /64 means the first 64 bits are the network portion.
				let prefixLength = NSNumber(value: range.networkPrefixLength)

				return (addressString, prefixLength)

			case .ipv4:
				// This is an IPv4 address, skip it.
				return nil
			}
		}

		// If no IPv6 addresses found, return nil.
		guard !ipv6Addresses.isEmpty else {
			return nil
		}

		// Extract addresses and prefix lengths into separate arrays.
		// NetworkExtension requires these as parallel arrays.
		let addresses = ipv6Addresses.map { $0.0 }
		let prefixLengths = ipv6Addresses.map { $0.1 }

		// Create the IPv6 settings object.
		let settings = NEIPv6Settings(addresses: addresses, networkPrefixLengths: prefixLengths)

		// Generate routes from peer allowed IPs.
		// Routes determine which destination IPv6 addresses use the tunnel.
		settings.includedRoutes = try generateIPv6Routes()

		return settings
	}

	/// Generates IPv6 routes from peer allowed IPs.
	///
	/// This method examines all peers and extracts their IPv6 allowed IPs.
	/// Each allowed IP range becomes a route in the tunnel settings.
	///
	/// For example, if a peer has allowedIPs = ["fd00::/64", "fd01::/48"],
	/// this creates two IPv6 routes pointing those networks through the tunnel.
	///
	/// A special case is "::/0" (the IPv6 default route), which means all IPv6
	/// traffic should go through the tunnel. This is full-tunneling for IPv6.
	///
	/// - Returns: Array of IPv6 routes
	/// - Throws: `IntegrationError.invalidRoute` if a route cannot be parsed
	private func generateIPv6Routes() throws -> [NEIPv6Route] {
		var routes: [NEIPv6Route] = []

		// Iterate through all peers in the configuration.
		for peer in configuration.peers {
			// Examine each allowed IP range for this peer.
			for allowedIP in peer.allowedIPs {
				// Check if this is an IPv6 range.
				switch allowedIP.address {
				case .ipv6(let ipv6Address):
					// Get the destination address as a string.
					let destinationAddress = ipv6Address.debugDescription

					// Get the network prefix length.
					// Unlike IPv4, IPv6 uses prefix lengths directly (not subnet masks).
					let prefixLength = NSNumber(value: allowedIP.networkPrefixLength)

					// Create the route object.
					let route = NEIPv6Route(
						destinationAddress: destinationAddress,
						networkPrefixLength: prefixLength
					)

					routes.append(route)

				case .ipv4:
					// This is an IPv4 allowed IP, skip it.
					// IPv4 routes are handled separately.
					continue
				}
			}
		}

		return routes
	}
}
