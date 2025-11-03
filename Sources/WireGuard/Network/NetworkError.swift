import Foundation

/// Errors that can occur during network addressing operations.
///
/// These errors cover endpoint parsing, IP address validation, CIDR notation parsing,
/// and DNS resolution operations for WireGuard network configurations.
public enum NetworkError: Error, LocalizedError, Sendable, Equatable {
	/// The endpoint format is invalid or cannot be parsed.
	///
	/// This occurs when attempting to parse an endpoint string that doesn't match
	/// the expected "host:port" format.
	case invalidEndpoint

	/// The IP address format is invalid or cannot be parsed.
	///
	/// This occurs when attempting to parse an IP address string that contains
	/// invalid characters or incorrect formatting.
	case invalidIPAddress

	/// The CIDR notation is invalid or malformed.
	///
	/// This occurs when attempting to parse a CIDR string that doesn't match
	/// the expected "address/prefix" format.
	case invalidCIDR

	/// The network prefix length is invalid for the address type.
	///
	/// This occurs when the prefix length is out of range (0-32 for IPv4,
	/// 0-128 for IPv6).
	case invalidPrefixLength

	/// DNS resolution failed for the hostname.
	///
	/// This occurs when the DNS resolver cannot find any addresses for the
	/// provided hostname.
	case resolutionFailed(String)

	/// DNS resolution timed out.
	///
	/// This occurs when the DNS resolver takes too long to respond and
	/// exceeds the configured timeout period.
	case resolutionTimeout

	/// A user-friendly description of the error.
	public var errorDescription: String? {
		switch self {
		case .invalidEndpoint:
			return "The endpoint format is invalid."
		case .invalidIPAddress:
			return "The IP address format is invalid."
		case .invalidCIDR:
			return "The CIDR notation is invalid or malformed."
		case .invalidPrefixLength:
			return "The network prefix length is invalid for the address type."
		case .resolutionFailed(let hostname):
			return "DNS resolution failed for hostname '\(hostname)'."
		case .resolutionTimeout:
			return "DNS resolution timed out."
		}
	}

	/// Suggested recovery options for the user.
	public var recoverySuggestion: String? {
		switch self {
		case .invalidEndpoint:
			return
				"Ensure the endpoint is in the format 'host:port' (e.g., '192.168.1.1:51820' or 'example.com:51820')."
		case .invalidIPAddress:
			return
				"Check that the IP address is valid IPv4 (e.g., '192.168.1.1') or IPv6 (e.g., '2001:db8::1')."
		case .invalidCIDR:
			return
				"Ensure the CIDR notation is in the format 'address/prefix' "
				+ "(e.g., '192.168.1.0/24' or '2001:db8::/32')."
		case .invalidPrefixLength:
			return "Use a prefix length between 0-32 for IPv4 addresses or 0-128 for IPv6 addresses."
		case .resolutionFailed:
			return "Check that the hostname is spelled correctly and that DNS is configured properly."
		case .resolutionTimeout:
			return
				"Check your network connection and try again. Consider using a direct IP address instead."
		}
	}

	/// Technical explanation of why the error occurred.
	public var failureReason: String? {
		switch self {
		case .invalidEndpoint:
			return "The provided string could not be parsed as a valid endpoint with host and port."
		case .invalidIPAddress:
			return "The IP address parser failed to parse the input string."
		case .invalidCIDR:
			return "The CIDR notation parser failed to parse the input string."
		case .invalidPrefixLength:
			return "The network prefix length is outside the valid range for the IP address type."
		case .resolutionFailed(let hostname):
			return
				"The DNS resolver could not find any IP addresses for the hostname '\(hostname)'."
		case .resolutionTimeout:
			return "The DNS resolver exceeded the maximum timeout period while resolving the hostname."
		}
	}
}
