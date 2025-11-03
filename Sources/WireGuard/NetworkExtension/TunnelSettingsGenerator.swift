import Foundation
import NetworkExtension

/// Generates NEPacketTunnelNetworkSettings from WireGuard tunnel configuration.
///
/// This is the primary integration point between TairaWireGuard and Apple's NetworkExtension
/// framework. NetworkExtension requires tunnel settings in a specific format (NEPacketTunnelNetworkSettings),
/// and this generator converts our TunnelConfiguration into that format.
///
/// # Usage
///
/// ```swift
/// let configuration = try TunnelConfiguration(...)
/// let generator = TunnelSettingsGenerator(
///     configuration: configuration,
///     tunnelRemoteAddress: "203.0.113.1"
/// )
/// let settings = try generator.generateNetworkSettings()
/// try await setTunnelNetworkSettings(settings)
/// ```
///
/// # Platform support
///
/// Works on both iOS 15.0+ and macOS 13.0+.
///
/// # Thread safety
///
/// This type is a struct and conforms to Sendable, making it safe to use across actor boundaries.
public struct TunnelSettingsGenerator: Sendable {

	/// The WireGuard tunnel configuration to convert.
	///
	/// This contains all the information needed to set up the tunnel: interface addresses,
	/// DNS servers, peer configurations, and routing rules.
	let configuration: TunnelConfiguration

	/// The remote address of the tunnel endpoint.
	///
	/// NetworkExtension requires this to be set. It's typically the IP address
	/// of the VPN server (the peer's endpoint address).
	///
	/// For configurations with multiple peers, use the address of the primary peer.
	let tunnelRemoteAddress: String

	/// Creates a new tunnel settings generator.
	///
	/// - Parameters:
	///   - configuration: The WireGuard tunnel configuration to convert
	///   - tunnelRemoteAddress: The IP address of the tunnel's remote endpoint (VPN server)
	public init(configuration: TunnelConfiguration, tunnelRemoteAddress: String) {
		self.configuration = configuration
		self.tunnelRemoteAddress = tunnelRemoteAddress
	}

	/// Generates NetworkExtension settings from the tunnel configuration.
	///
	/// This method converts the WireGuard configuration into the format required by
	/// NetworkExtension. It generates:
	/// - IPv4 settings (if the configuration has IPv4 addresses)
	/// - IPv6 settings (if the configuration has IPv6 addresses)
	/// - DNS settings (if DNS servers are configured)
	/// - Routes (from peer allowed IPs)
	/// - MTU configuration (if specified)
	///
	/// # Errors
	///
	/// Throws `IntegrationError` if:
	/// - The configuration is invalid or incomplete
	/// - Routes cannot be parsed
	/// - DNS servers cannot be parsed
	///
	/// # Example
	///
	/// ```swift
	/// let generator = TunnelSettingsGenerator(
	///     configuration: tunnelConfig,
	///     tunnelRemoteAddress: "203.0.113.1"
	/// )
	/// let settings = try generator.generateNetworkSettings()
	/// ```
	///
	/// - Returns: NetworkExtension settings ready to apply to the tunnel
	/// - Throws: `IntegrationError` if settings cannot be generated
	public func generateNetworkSettings() throws -> NEPacketTunnelNetworkSettings {
		// Create the base settings object with the tunnel remote address.
		// This is required by NetworkExtension.
		let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)

		// Generate and apply IPv4 settings if the configuration has IPv4 addresses.
		// IPv4 settings include the tunnel's IP address, subnet mask, and routes.
		if let ipv4Settings = try generateIPv4Settings() {
			settings.ipv4Settings = ipv4Settings
		}

		// Generate and apply IPv6 settings if the configuration has IPv6 addresses.
		// IPv6 settings include the tunnel's IP address, prefix length, and routes.
		if let ipv6Settings = try generateIPv6Settings() {
			settings.ipv6Settings = ipv6Settings
		}

		// Generate and apply DNS settings if DNS servers are configured.
		// DNS settings control which DNS servers are used while the tunnel is active.
		if let dnsSettings = generateDNSSettings() {
			settings.dnsSettings = dnsSettings
		}

		// Apply MTU configuration if specified.
		// MTU (Maximum Transmission Unit) controls the maximum packet size.
		if let mtu = configuration.interface.mtu {
			settings.mtu = NSNumber(value: mtu)
		}

		return settings
	}
}
