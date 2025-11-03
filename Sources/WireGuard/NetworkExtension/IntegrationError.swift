import Foundation

/// Errors that can occur during NetworkExtension integration.
///
/// This error type covers problems specific to integrating WireGuard with Apple's
/// NetworkExtension framework. NetworkExtension is the framework that powers VPN
/// functionality on iOS and macOS.
///
/// These errors help developers identify configuration problems, invalid settings,
/// or runtime issues when setting up or running a VPN tunnel.
///
/// # Error categories
///
/// This error type covers several categories of problems:
/// - **Address errors**: Missing IPv4 or IPv6 addresses in the configuration
/// - **Route errors**: Invalid or malformed routing rules
/// - **DNS errors**: Invalid DNS server addresses
/// - **Settings errors**: Problems generating NetworkExtension settings
/// - **Runtime errors**: Problems with packet flow during tunnel operation
///
/// # Example
///
/// ```swift
/// do {
///     let settings = try generator.generateNetworkSettings()
/// } catch IntegrationError.noIPv4Address {
///     print("Configuration needs at least one IPv4 address")
/// } catch {
///     print("Unexpected error: \(error)")
/// }
/// ```
///
/// # Thread safety
///
/// This type conforms to `Sendable`, meaning it can be safely shared across
/// concurrency boundaries (actors, tasks, etc.) in Swift 6 applications.
public enum IntegrationError: Error, Sendable, Equatable {

	// MARK: - Error cases

	/// The configuration has no IPv4 address.
	///
	/// NetworkExtension requires at least one IPv4 address to be configured
	/// on the tunnel interface. This error occurs when trying to generate
	/// IPv4 settings but finding no IPv4 addresses in the configuration.
	///
	/// # Recovery
	///
	/// Add at least one IPv4 address to the interface configuration's
	/// addresses array. The address should be in CIDR notation (e.g., "10.0.0.2/24").
	case noIPv4Address

	/// The configuration has no IPv6 address.
	///
	/// Similar to `noIPv4Address`, this error occurs when attempting to generate
	/// IPv6 settings but finding no IPv6 addresses in the configuration.
	///
	/// # Recovery
	///
	/// Add at least one IPv6 address to the interface configuration's
	/// addresses array. The address should be in CIDR notation (e.g., "fd00::2/64").
	case noIPv6Address

	/// An invalid route was found in the configuration.
	///
	/// Routes define which IP addresses should be sent through the VPN tunnel.
	/// This error occurs when a route cannot be parsed or is in an invalid format.
	///
	/// The associated value contains the problematic route string, which helps
	/// developers identify exactly which route in their configuration is invalid.
	///
	/// # Recovery
	///
	/// Verify all allowedIPs in peer configurations are valid CIDR notation.
	/// Examples of valid routes: "0.0.0.0/0", "192.168.1.0/24", "::/0", "fd00::/64".
	///
	/// - Parameter route: The invalid route string that caused the error
	case invalidRoute(String)

	/// An invalid DNS server address was found in the configuration.
	///
	/// DNS servers must be valid IP addresses (either IPv4 or IPv6), not hostnames.
	/// This error occurs when a DNS server cannot be parsed as a valid IP address.
	///
	/// The associated value contains the problematic DNS string, which helps
	/// developers identify which DNS server in their configuration is invalid.
	///
	/// # Recovery
	///
	/// Verify all DNS servers are valid IP addresses. Examples: "8.8.8.8", "1.1.1.1",
	/// "2001:4860:4860::8888". Hostnames like "dns.google.com" are not allowed.
	///
	/// - Parameter dns: The invalid DNS string that caused the error
	case invalidDNS(String)

	/// Failed to generate NetworkExtension settings from the configuration.
	///
	/// This is a general error that occurs when something goes wrong during
	/// the process of converting a WireGuard configuration into the settings
	/// format required by NetworkExtension.
	///
	/// The associated value contains a description of what went wrong, which
	/// helps developers understand the specific problem.
	///
	/// # Recovery
	///
	/// Check the error message for details about what failed. Common causes include:
	/// - Missing required configuration fields
	/// - Invalid configuration values
	/// - Unsupported configuration combinations
	///
	/// - Parameter reason: Description of why settings generation failed
	case settingsGenerationFailed(String)

	/// An error occurred during packet flow operations.
	///
	/// Packet flow errors occur at runtime when reading from or writing to the
	/// tunnel's packet flow. The packet flow is how data moves in and out of
	/// the VPN tunnel.
	///
	/// The associated value contains details about the packet flow error, which
	/// helps developers debug runtime connection problems.
	///
	/// # Recovery
	///
	/// Packet flow errors usually indicate network connectivity problems or
	/// tunnel state issues. Try:
	/// - Reconnecting the tunnel
	/// - Checking network connectivity
	/// - Verifying the tunnel hasn't been disconnected
	///
	/// - Parameter message: Description of the packet flow error
	case packetFlowError(String)
}
