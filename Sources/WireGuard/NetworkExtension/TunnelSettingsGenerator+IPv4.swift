import Foundation
import Network
import NetworkExtension

/// Extension for generating IPv4 network settings.
///
/// This extension handles the conversion of IPv4 configuration from WireGuard format
/// to NetworkExtension format. It extracts IPv4 addresses from the interface configuration
/// and creates the appropriate NEIPv4Settings object.
extension TunnelSettingsGenerator {

	/// Generates IPv4 settings from the tunnel configuration.
	///
	/// This method examines the interface addresses and extracts IPv4 addresses.
	/// For each IPv4 address, it creates an NEIPv4Settings object with:
	/// - The IP address (e.g., "10.0.0.2")
	/// - The subnet mask calculated from CIDR prefix (e.g., "255.255.255.0" for /24)
	/// - Routes generated from peer allowed IPs
	///
	/// If no IPv4 addresses are configured, this returns nil and no IPv4 settings
	/// will be applied to the tunnel.
	///
	/// - Returns: IPv4 settings if IPv4 addresses are configured, nil otherwise
	/// - Throws: `IntegrationError` if IPv4 routes cannot be generated
	func generateIPv4Settings() throws -> NEIPv4Settings? {
		// Extract IPv4 addresses from the interface configuration.
		// Interface addresses are stored as IPAddressRange objects in CIDR notation.
		let ipv4Addresses = configuration.interface.addresses.compactMap { range -> (String, String)? in
			// Check if this address is IPv4.
			// IPAddressRange can contain either IPv4 or IPv6 addresses.
			switch range.address {
			case .ipv4(let ipv4Address):
				// Extract the address string.
				let addressString = ipv4Address.debugDescription

				// Calculate the subnet mask from the CIDR prefix length.
				// For example, /24 becomes 255.255.255.0.
				let subnetMask = subnetMaskFromPrefix(range.networkPrefixLength, isIPv6: false)

				return (addressString, subnetMask)

			case .ipv6:
				// This is an IPv6 address, skip it.
				return nil
			}
		}

		// If no IPv4 addresses found, return nil.
		// This indicates the tunnel should not have IPv4 configured.
		guard !ipv4Addresses.isEmpty else {
			return nil
		}

		// Extract just the addresses and subnet masks into separate arrays.
		// NetworkExtension requires these as parallel arrays.
		let addresses = ipv4Addresses.map { $0.0 }
		let subnetMasks = ipv4Addresses.map { $0.1 }

		// Create the IPv4 settings object.
		// We use the first address as the primary address.
		let settings = NEIPv4Settings(addresses: addresses, subnetMasks: subnetMasks)

		// Generate routes from peer allowed IPs.
		// Routes determine which destination IPs are sent through the tunnel.
		settings.includedRoutes = try generateIPv4Routes()

		return settings
	}

	/// Generates IPv4 routes from peer allowed IPs.
	///
	/// This method examines all peers and extracts their IPv4 allowed IPs.
	/// Each allowed IP range becomes a route in the tunnel settings.
	///
	/// For example, if a peer has allowedIPs = ["192.168.1.0/24", "10.0.0.0/8"],
	/// this creates two IPv4 routes pointing those networks through the tunnel.
	///
	/// A special case is "0.0.0.0/0" (the default route), which means all IPv4
	/// traffic should go through the tunnel. This is called full-tunneling.
	///
	/// - Returns: Array of IPv4 routes
	/// - Throws: `IntegrationError.invalidRoute` if a route cannot be parsed
	private func generateIPv4Routes() throws -> [NEIPv4Route] {
		var routes: [NEIPv4Route] = []

		// Iterate through all peers in the configuration.
		for peer in configuration.peers {
			// Examine each allowed IP range for this peer.
			for allowedIP in peer.allowedIPs {
				// Check if this is an IPv4 range.
				switch allowedIP.address {
				case .ipv4(let ipv4Address):
					// Get the destination address as a string.
					let destinationAddress = ipv4Address.debugDescription

					// Calculate the subnet mask from the prefix length.
					let subnetMask = subnetMaskFromPrefix(
						allowedIP.networkPrefixLength, isIPv6: false)

					// Create the route object.
					let route = NEIPv4Route(
						destinationAddress: destinationAddress,
						subnetMask: subnetMask
					)

					routes.append(route)

				case .ipv6:
					// This is an IPv6 allowed IP, skip it.
					// IPv6 routes are handled separately.
					continue
				}
			}
		}

		return routes
	}

	/// Converts a CIDR prefix length to a subnet mask string.
	///
	/// CIDR notation uses a prefix length (e.g., /24) to specify the network size.
	/// Subnet masks use dotted decimal notation (e.g., 255.255.255.0).
	/// This function converts between the two formats.
	///
	/// # Examples
	///
	/// - /8 → 255.0.0.0
	/// - /16 → 255.255.0.0
	/// - /24 → 255.255.255.0
	/// - /32 → 255.255.255.255 (single host)
	///
	/// For IPv6, this returns the prefix length as a string since IPv6 doesn't
	/// use dotted decimal subnet masks.
	///
	/// - Parameters:
	///   - prefixLength: The CIDR prefix length (0-32 for IPv4, 0-128 for IPv6)
	///   - isIPv6: Whether this is for an IPv6 address
	/// - Returns: Subnet mask string for IPv4, or prefix length string for IPv6
	private func subnetMaskFromPrefix(_ prefixLength: UInt8, isIPv6: Bool) -> String {
		// IPv6 uses prefix lengths, not subnet masks.
		if isIPv6 {
			return "\(prefixLength)"
		}

		// For IPv4, convert the prefix length to a 32-bit mask.
		// A prefix length of N means the first N bits are 1, the rest are 0.
		//
		// For example, /24 means:
		// 11111111.11111111.11111111.00000000 = 255.255.255.0
		let mask: UInt32
		if prefixLength == 0 {
			// Special case: /0 means no network bits, all host bits.
			mask = 0
		} else {
			// Create a mask with the first `prefixLength` bits set to 1.
			// We do this by shifting left from the most significant bit.
			mask = UInt32.max << (32 - prefixLength)
		}

		// Convert the 32-bit mask to dotted decimal notation.
		// Split the 32 bits into four 8-bit octets.
		let octet1 = (mask >> 24) & 0xFF
		let octet2 = (mask >> 16) & 0xFF
		let octet3 = (mask >> 8) & 0xFF
		let octet4 = mask & 0xFF

		return "\(octet1).\(octet2).\(octet3).\(octet4)"
	}
}
