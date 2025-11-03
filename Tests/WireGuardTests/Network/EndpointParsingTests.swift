import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for Endpoint parsing functionality.
///
/// These tests verify endpoint parsing and string representation for IPv4, IPv6,
/// and hostname endpoints. This file focuses on successful parsing scenarios and
/// round-trip serialization.
///
/// Test coverage includes:
/// - IPv4 endpoint parsing and formatting
/// - IPv6 endpoint parsing with bracket notation
/// - Hostname endpoint parsing
/// - Port validation (1-65535)
/// - Round-trip serialization
///
/// See also: EndpointValidationTests.swift for invalid format and equality tests.
struct EndpointParsingTests {
	// MARK: - IPv4 endpoint tests

	/// Verifies that an IPv4 address with port can be parsed correctly.
	///
	/// This tests the most common endpoint format: "address:port". The parser must
	/// recognize the IPv4 address and extract both the host and port components.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:51820" should parse successfully
	/// - Host should be recognized as IPv4 variant with correct address
	/// - Port should be extracted as UInt16 value 51820
	@Test("Endpoint parses IPv4 address with port")
	func parseIPv4WithPort() throws {
		let endpointString = "192.168.1.1:51820"
		let endpoint = try #require(Endpoint(from: endpointString))

		if case .ipv4(let address) = endpoint.host {
			#expect(address.debugDescription == "192.168.1.1")
		} else {
			Issue.record("Expected IPv4 host, got \(endpoint.host)")
		}

		#expect(endpoint.port == 51820)
	}

	/// Verifies that IPv4 endpoints format correctly as strings.
	///
	/// The string representation must match the standard "address:port" format
	/// for compatibility with WireGuard configuration files.
	///
	/// Expected behavior:
	/// - Input "10.0.0.1:8080" should produce identical string representation
	/// - No extra whitespace or formatting changes
	@Test("Endpoint formats IPv4 correctly")
	func formatIPv4() throws {
		let endpoint = try #require(Endpoint(from: "10.0.0.1:8080"))
		#expect(endpoint.stringRepresentation == "10.0.0.1:8080")
	}

	// MARK: - IPv6 endpoint tests

	/// Verifies that IPv6 addresses with bracket notation and port can be parsed.
	///
	/// IPv6 addresses contain colons, so bracket notation "[address]:port" is required
	/// to disambiguate the address colons from the port separator. This is standard
	/// for IPv6 in URL and configuration formats.
	///
	/// Expected behavior:
	/// - Input "[2001:db8::1]:51820" should parse successfully
	/// - Host should be recognized as IPv6 variant
	/// - Brackets should be stripped from the parsed address
	/// - Port should be extracted correctly
	@Test("Endpoint parses IPv6 address with brackets and port")
	func parseIPv6WithBracketsAndPort() throws {
		let endpointString = "[2001:db8::1]:51820"
		let endpoint = try #require(Endpoint(from: endpointString))

		if case .ipv6(let address) = endpoint.host {
			#expect(address.debugDescription == "2001:db8::1")
		} else {
			Issue.record("Expected IPv6 host, got \(endpoint.host)")
		}

		#expect(endpoint.port == 51820)
	}

	/// Verifies that IPv6 endpoints format with bracket notation.
	///
	/// When converting IPv6 endpoints to strings, brackets must be added around
	/// the address to maintain the standard format required by WireGuard configs.
	///
	/// Expected behavior:
	/// - Input "[::1]:8080" should produce identical string representation
	/// - Brackets must be present in output
	@Test("Endpoint formats IPv6 with brackets")
	func formatIPv6WithBrackets() throws {
		let endpoint = try #require(Endpoint(from: "[::1]:8080"))
		#expect(endpoint.stringRepresentation == "[::1]:8080")
	}

	/// Verifies that fully expanded IPv6 addresses can be parsed.
	///
	/// IPv6 addresses can be written in compressed form (using ::) or fully expanded.
	/// The parser must handle both forms correctly using the Network framework's
	/// IPv6Address type.
	///
	/// Expected behavior:
	/// - Full notation "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443" should parse
	/// - Should be recognized as IPv6 (not hostname)
	/// - Port should be extracted correctly
	@Test("Endpoint parses full IPv6 address")
	func parseFullIPv6() throws {
		let endpointString = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443"
		let endpoint = try #require(Endpoint(from: endpointString))

		if case .ipv6 = endpoint.host {
			// Success - verified it's IPv6
		} else {
			Issue.record("Expected IPv6 host for full address notation")
		}

		#expect(endpoint.port == 443)
	}

	// MARK: - Hostname endpoint tests

	/// Verifies that DNS hostnames with port can be parsed.
	///
	/// WireGuard supports hostnames for endpoints, which are resolved to IP addresses
	/// at connection time. This allows endpoints to use dynamic DNS or update their
	/// IP address without reconfiguration.
	///
	/// Expected behavior:
	/// - Input "vpn.example.com:51820" should parse successfully
	/// - Host should be stored as name variant (not IPv4/IPv6)
	/// - Hostname string should be preserved exactly
	/// - Port should be extracted correctly
	@Test("Endpoint parses hostname with port")
	func parseHostnameWithPort() throws {
		let endpointString = "vpn.example.com:51820"
		let endpoint = try #require(Endpoint(from: endpointString))

		if case .name(let hostname) = endpoint.host {
			#expect(hostname == "vpn.example.com")
		} else {
			Issue.record("Expected hostname, got \(endpoint.host)")
		}

		#expect(endpoint.port == 51820)
	}

	/// Verifies that hostname endpoints format correctly as strings.
	///
	/// Hostname formatting is simpler than IPv6 since no brackets are needed.
	/// The format should be "hostname:port" with no modifications.
	///
	/// Expected behavior:
	/// - Input "example.com:443" should produce identical string representation
	/// - Hostname should not be modified or normalized
	@Test("Endpoint formats hostname correctly")
	func formatHostname() throws {
		let endpoint = try #require(Endpoint(from: "example.com:443"))
		#expect(endpoint.stringRepresentation == "example.com:443")
	}

	/// Verifies that multi-level subdomain hostnames are handled correctly.
	///
	/// Complex DNS names with multiple subdomains should be preserved exactly.
	/// This ensures compatibility with real-world DNS configurations.
	///
	/// Expected behavior:
	/// - Input "server.vpn.example.com:51820" should parse successfully
	/// - Entire hostname should be preserved without modification
	@Test("Endpoint parses subdomain hostname")
	func parseSubdomainHostname() throws {
		let endpointString = "server.vpn.example.com:51820"
		let endpoint = try #require(Endpoint(from: endpointString))

		if case .name(let hostname) = endpoint.host {
			#expect(hostname == "server.vpn.example.com")
		} else {
			Issue.record("Expected hostname for subdomain")
		}
	}

	// MARK: - Port range tests

	/// Verifies that port 1 (minimum valid port) is accepted.
	///
	/// Port 1 is the lowest valid port number. While rarely used for WireGuard,
	/// it must be accepted to support the full valid range.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:1" should parse successfully
	/// - Port value should be exactly 1
	@Test("Endpoint accepts minimum valid port")
	func acceptMinimumValidPort() throws {
		let endpointString = "192.168.1.1:1"
		let endpoint = try #require(Endpoint(from: endpointString))
		#expect(endpoint.port == 1)
	}

	/// Verifies that port 65535 (maximum valid port) is accepted.
	///
	/// Port 65535 is the highest valid port number (UInt16.max).
	/// This tests the upper boundary of the valid range.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:65535" should parse successfully
	/// - Port value should be exactly 65535
	@Test("Endpoint accepts maximum valid port")
	func acceptMaximumValidPort() throws {
		let endpointString = "192.168.1.1:65535"
		let endpoint = try #require(Endpoint(from: endpointString))
		#expect(endpoint.port == 65535)
	}

	/// Verifies that the standard WireGuard port (51820) is accepted.
	///
	/// Port 51820 is the conventional default port for WireGuard.
	/// This tests a common real-world value.
	///
	/// Expected behavior:
	/// - Input "10.0.0.1:51820" should parse successfully
	/// - Port value should be exactly 51820
	@Test("Endpoint accepts common WireGuard port")
	func acceptCommonWireGuardPort() throws {
		let endpointString = "10.0.0.1:51820"
		let endpoint = try #require(Endpoint(from: endpointString))
		#expect(endpoint.port == 51820)
	}

	// MARK: - Round-trip tests

	/// Verifies that IPv4 endpoints round-trip through string serialization.
	///
	/// Converting an endpoint to a string and back should produce an equal endpoint.
	/// This is critical for reading and writing configuration files reliably.
	///
	/// Expected behavior:
	/// - Parse "192.168.1.1:51820" -> convert to string -> parse again
	/// - Final endpoint should equal original
	@Test("Endpoint round-trips through string representation")
	func roundTripThroughString() throws {
		let original = try #require(Endpoint(from: "192.168.1.1:51820"))
		let stringRep = original.stringRepresentation
		let roundTripped = try #require(Endpoint(from: stringRep))
		#expect(original == roundTripped)
	}

	/// Verifies that IPv6 endpoints round-trip through string serialization.
	///
	/// IPv6 round-tripping is especially important because bracket notation must
	/// be preserved correctly through the serialization cycle.
	///
	/// Expected behavior:
	/// - Parse "[2001:db8::1]:51820" -> convert to string -> parse again
	/// - Final endpoint should equal original
	/// - Brackets should be preserved in string representation
	@Test("IPv6 endpoint round-trips through string representation")
	func ipv6RoundTripThroughString() throws {
		let original = try #require(Endpoint(from: "[2001:db8::1]:51820"))
		let stringRep = original.stringRepresentation
		let roundTripped = try #require(Endpoint(from: stringRep))
		#expect(original == roundTripped)
	}
}
