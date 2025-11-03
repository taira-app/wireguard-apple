import Foundation

/// Extension providing user-friendly error messages for IntegrationError.
///
/// The LocalizedError protocol is part of Foundation and provides a standard way
/// to give errors human-readable descriptions. When errors conform to LocalizedError,
/// they can provide error descriptions, failure reasons, and recovery suggestions.
extension IntegrationError: LocalizedError {

	/// A user-facing description of the error.
	///
	/// This is the primary error message that users and developers will see.
	/// It should clearly explain what went wrong in simple language.
	public var errorDescription: String? {
		switch self {
		case .noIPv4Address:
			return "No IPv4 address configured on tunnel interface"

		case .noIPv6Address:
			return "No IPv6 address configured on tunnel interface"

		case .invalidRoute(let route):
			return "Invalid route '\(route)' in peer configuration"

		case .invalidDNS(let dns):
			return "Invalid DNS server '\(dns)' in configuration"

		case .settingsGenerationFailed(let reason):
			return "Failed to generate network settings: \(reason)"

		case .packetFlowError(let message):
			return "Packet flow error: \(message)"
		}
	}

	/// A technical explanation of why the error occurred.
	///
	/// The failure reason provides more context about the underlying cause of
	/// the error. This is useful for developers who need to understand the
	/// technical details.
	public var failureReason: String? {
		switch self {
		case .noIPv4Address:
			return "NetworkExtension requires at least one IPv4 address to configure tunnel interface"

		case .noIPv6Address:
			return "NetworkExtension requires at least one IPv6 address when configuring IPv6 tunnel"

		case .invalidRoute(let route):
			return "Route '\(route)' could not be parsed as valid CIDR notation"

		case .invalidDNS(let dns):
			return "DNS server '\(dns)' is not a valid IPv4 or IPv6 address"

		case .settingsGenerationFailed(let reason):
			return "Configuration could not be converted to NetworkExtension settings: \(reason)"

		case .packetFlowError(let message):
			return "Communication with tunnel packet flow failed: \(message)"
		}
	}

	/// Suggestions for how to fix the error.
	///
	/// The recovery suggestion tells developers what action they should take
	/// to resolve the error. Good recovery suggestions are specific and actionable.
	public var recoverySuggestion: String? {
		switch self {
		case .noIPv4Address:
			return "Add at least one IPv4 address to the interface configuration (e.g., '10.0.0.2/24')"

		case .noIPv6Address:
			return "Add at least one IPv6 address to the interface configuration (e.g., 'fd00::2/64')"

		case .invalidRoute:
			return
				"Ensure all peer allowedIPs use valid CIDR notation "
				+ "(e.g., '0.0.0.0/0' for all IPv4, or '192.168.1.0/24' for a subnet)"

		case .invalidDNS:
			return
				"Use valid IP addresses for DNS servers (e.g., '8.8.8.8' for Google DNS, or '1.1.1.1' for Cloudflare DNS)"

		case .settingsGenerationFailed:
			return
				"Review the tunnel configuration to ensure all required fields are present and valid"

		case .packetFlowError:
			return
				"Try reconnecting the tunnel, or check network connectivity and tunnel state"
		}
	}
}
