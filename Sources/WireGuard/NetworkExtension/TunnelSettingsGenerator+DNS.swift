import Foundation
import NetworkExtension

/// Extension for generating DNS settings.
///
/// This extension handles the conversion of DNS configuration from WireGuard format
/// to NetworkExtension format. It extracts DNS servers and search domains from the
/// interface configuration and creates the appropriate NEDNSSettings object.
extension TunnelSettingsGenerator {

	/// Generates DNS settings from the tunnel configuration.
	///
	/// This method examines the interface DNS configuration and creates NEDNSSettings
	/// if DNS servers are specified. The DNS settings control which DNS servers are
	/// used while the VPN tunnel is active.
	///
	/// DNS configuration includes:
	/// - DNS server IP addresses (both IPv4 and IPv6)
	/// - DNS search domains (for automatic domain suffix completion)
	///
	/// If no DNS servers are configured, this returns nil and the system's default
	/// DNS configuration will be used.
	///
	/// - Returns: DNS settings if DNS servers are configured, nil otherwise
	func generateDNSSettings() -> NEDNSSettings? {
		// Extract DNS server addresses from the interface configuration.
		let dnsServers = configuration.interface.dns.map { dnsServer -> String in
			// Convert the DNSServer object to a string IP address.
			// DNS servers can be either IPv4 or IPv6 addresses.
			switch dnsServer.address {
			case .ipv4(let ipv4Address):
				// Return the IPv4 address as a string.
				return ipv4Address.debugDescription

			case .ipv6(let ipv6Address):
				// Return the IPv6 address as a string.
				return ipv6Address.debugDescription
			}
		}

		// If no DNS servers are configured, return nil.
		// This means the system's default DNS will be used.
		guard !dnsServers.isEmpty else {
			return nil
		}

		// Create the DNS settings object with the server addresses.
		let settings = NEDNSSettings(servers: dnsServers)

		// Add DNS search domains if configured.
		// Search domains are automatically appended to short hostnames.
		// For example, with search domain "example.com", looking up "server"
		// will try "server.example.com".
		if !configuration.interface.dnsSearch.isEmpty {
			settings.searchDomains = configuration.interface.dnsSearch
		}

		return settings
	}
}
