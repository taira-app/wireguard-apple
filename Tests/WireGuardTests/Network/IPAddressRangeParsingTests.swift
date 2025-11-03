import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for IPAddressRange parsing functionality.
///
/// These tests verify CIDR notation parsing and formatting for both IPv4 and IPv6
/// address ranges. This file focuses on successful parsing scenarios, round-trip
/// serialization, and helper properties.
///
/// IP address ranges are used in WireGuard for:
/// - Allowed IPs (which traffic to route through the tunnel)
/// - Interface addresses (what IP addresses the interface has)
///
/// Test coverage includes:
/// - IPv4 CIDR parsing and formatting
/// - IPv6 CIDR parsing and formatting
/// - Single host addresses (/32 and /128)
/// - Full-range addresses (/0)
/// - Round-trip serialization
/// - Helper property tests
///
/// See also: IPAddressRangeValidationTests.swift for invalid format and equality tests.
struct IPAddressRangeParsingTests {
	// MARK: - IPv4 CIDR tests

	/// Verifies that IPv4 CIDR notation can be parsed correctly.
	///
	/// CIDR notation combines an IP address with a prefix length to define a subnet.
	/// For example, "192.168.1.0/24" represents all addresses from 192.168.1.0 to
	/// 192.168.1.255 (256 addresses total).
	///
	/// Expected behavior:
	/// - Input "192.168.1.0/24" should parse successfully
	/// - Address should be recognized as IPv4
	/// - Prefix length should be exactly 24
	@Test("IPAddressRange parses IPv4 CIDR notation")
	func parseIPv4CIDR() throws {
		let cidrString = "192.168.1.0/24"
		let range = try #require(IPAddressRange(from: cidrString))

		if case .ipv4(let address) = range.address {
			#expect(address.debugDescription == "192.168.1.0")
		} else {
			Issue.record("Expected IPv4 address")
		}

		#expect(range.networkPrefixLength == 24)
	}

	/// Verifies that IPv4 address ranges format correctly in CIDR notation.
	///
	/// The string representation must match standard CIDR format "address/prefix"
	/// for compatibility with WireGuard configuration files.
	///
	/// Expected behavior:
	/// - Input "10.0.0.0/8" should produce identical string representation
	/// - No extra whitespace or formatting changes
	@Test("IPAddressRange formats IPv4 as CIDR")
	func formatIPv4AsCIDR() throws {
		let range = try #require(IPAddressRange(from: "10.0.0.0/8"))
		#expect(range.stringRepresentation == "10.0.0.0/8")
	}

	/// Verifies that IPv4 single host addresses (/32) are accepted.
	///
	/// A /32 prefix means all 32 bits are fixed, representing a single IP address.
	/// This is common in WireGuard configurations for interface addresses.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1/32" should parse successfully
	/// - isSingleHost property should return true
	/// - Prefix length should be 32
	@Test("IPAddressRange accepts IPv4 single host (/32)")
	func acceptIPv4SingleHost() throws {
		let range = try #require(IPAddressRange(from: "192.168.1.1/32"))

		#expect(range.networkPrefixLength == 32)
		#expect(range.isSingleHost == true)
		#expect(range.maxPrefixLength == 32)
	}

	/// Verifies that IPv4 full-range addresses (/0) are accepted.
	///
	/// A /0 prefix means no bits are fixed, representing all possible IPv4 addresses.
	/// This is used in WireGuard to route all traffic through the tunnel (full VPN).
	///
	/// Expected behavior:
	/// - Input "0.0.0.0/0" should parse successfully
	/// - isAllAddresses property should return true
	/// - Prefix length should be 0
	@Test("IPAddressRange accepts IPv4 all addresses (/0)")
	func acceptIPv4AllAddresses() throws {
		let range = try #require(IPAddressRange(from: "0.0.0.0/0"))

		#expect(range.networkPrefixLength == 0)
		#expect(range.isAllAddresses == true)
	}

	/// Verifies that IPv4 common subnet masks are accepted.
	///
	/// Tests various common subnet sizes used in real networks.
	/// These are the most frequently used prefix lengths in practice.
	///
	/// Expected behavior:
	/// - /8, /16, /24 prefixes should all parse successfully
	/// - Prefix lengths should match input values
	@Test("IPAddressRange accepts common IPv4 subnet sizes")
	func acceptCommonIPv4Subnets() throws {
		let subnets = [
			("10.0.0.0/8", UInt8(8)),  // Class A
			("172.16.0.0/16", UInt8(16)),  // Class B
			("192.168.0.0/24", UInt8(24))  // Class C
		]

		for (cidr, expectedPrefix) in subnets {
			let range = try #require(IPAddressRange(from: cidr))
			#expect(range.networkPrefixLength == expectedPrefix)
		}
	}

	// MARK: - IPv6 CIDR tests

	/// Verifies that IPv6 CIDR notation can be parsed correctly.
	///
	/// IPv6 uses the same CIDR notation as IPv4 but with 128-bit addresses.
	/// IPv6 addresses can be written in compressed form using :: notation.
	///
	/// Expected behavior:
	/// - Input "2001:db8::/32" should parse successfully
	/// - Address should be recognized as IPv6
	/// - Prefix length should be exactly 32
	@Test("IPAddressRange parses IPv6 CIDR notation")
	func parseIPv6CIDR() throws {
		let cidrString = "2001:db8::/32"
		let range = try #require(IPAddressRange(from: cidrString))

		if case .ipv6(let address) = range.address {
			#expect(address.debugDescription == "2001:db8::")
		} else {
			Issue.record("Expected IPv6 address")
		}

		#expect(range.networkPrefixLength == 32)
	}

	/// Verifies that IPv6 address ranges format correctly in CIDR notation.
	///
	/// IPv6 formatting should preserve the compressed notation where appropriate.
	/// The Network framework handles IPv6 compression automatically.
	///
	/// Expected behavior:
	/// - Input "fd00::/8" should produce string representation with compression
	/// - Format should be valid CIDR notation
	@Test("IPAddressRange formats IPv6 as CIDR")
	func formatIPv6AsCIDR() throws {
		let range = try #require(IPAddressRange(from: "fd00::/8"))
		#expect(range.stringRepresentation.contains("/8"))

		if case .ipv6 = range.address {
			// Verified it's IPv6
		} else {
			Issue.record("Expected IPv6 address")
		}
	}

	/// Verifies that IPv6 single host addresses (/128) are accepted.
	///
	/// A /128 prefix means all 128 bits are fixed, representing a single IPv6 address.
	/// This is the IPv6 equivalent of IPv4's /32.
	///
	/// Expected behavior:
	/// - Input "2001:db8::1/128" should parse successfully
	/// - isSingleHost property should return true
	/// - Prefix length should be 128
	/// - maxPrefixLength should be 128 for IPv6
	@Test("IPAddressRange accepts IPv6 single host (/128)")
	func acceptIPv6SingleHost() throws {
		let range = try #require(IPAddressRange(from: "2001:db8::1/128"))

		#expect(range.networkPrefixLength == 128)
		#expect(range.isSingleHost == true)
		#expect(range.maxPrefixLength == 128)
	}

	/// Verifies that IPv6 full-range addresses (::/0) are accepted.
	///
	/// A ::/0 prefix represents all possible IPv6 addresses.
	/// This is used to route all IPv6 traffic through the tunnel.
	///
	/// Expected behavior:
	/// - Input "::/0" should parse successfully
	/// - isAllAddresses property should return true
	/// - Prefix length should be 0
	@Test("IPAddressRange accepts IPv6 all addresses (::/0)")
	func acceptIPv6AllAddresses() throws {
		let range = try #require(IPAddressRange(from: "::/0"))

		#expect(range.networkPrefixLength == 0)
		#expect(range.isAllAddresses == true)
	}

	/// Verifies that IPv6 common prefix lengths are accepted.
	///
	/// Tests various common IPv6 subnet sizes. /64 is the standard subnet size
	/// for IPv6 networks, while /48 and /56 are common for site allocations.
	///
	/// Expected behavior:
	/// - /48, /56, /64 prefixes should all parse successfully
	/// - Prefix lengths should match input values
	@Test("IPAddressRange accepts common IPv6 prefix lengths")
	func acceptCommonIPv6Prefixes() throws {
		let subnets = [
			("2001:db8::/48", UInt8(48)),  // Site prefix
			("2001:db8::/56", UInt8(56)),  // Smaller site
			("2001:db8::/64", UInt8(64))  // Standard subnet
		]

		for (cidr, expectedPrefix) in subnets {
			let range = try #require(IPAddressRange(from: cidr))
			#expect(range.networkPrefixLength == expectedPrefix)
		}
	}

	// MARK: - Round-trip tests

	/// Verifies that IPv4 address ranges round-trip through string serialization.
	///
	/// Converting a range to a string and back should produce an equal range.
	/// This is critical for configuration file reliability.
	///
	/// Expected behavior:
	/// - Parse "192.168.1.0/24" -> convert to string -> parse again
	/// - Final range should equal original
	@Test("IPv4 IPAddressRange round-trips through string")
	func ipv4RoundTripThroughString() throws {
		let original = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let stringRep = original.stringRepresentation
		let roundTripped = try #require(IPAddressRange(from: stringRep))
		#expect(original == roundTripped)
	}

	/// Verifies that IPv6 address ranges round-trip through string serialization.
	///
	/// IPv6 round-tripping must handle compressed notation correctly.
	///
	/// Expected behavior:
	/// - Parse "2001:db8::/32" -> convert to string -> parse again
	/// - Final range should equal original
	@Test("IPv6 IPAddressRange round-trips through string")
	func ipv6RoundTripThroughString() throws {
		let original = try #require(IPAddressRange(from: "2001:db8::/32"))
		let stringRep = original.stringRepresentation
		let roundTripped = try #require(IPAddressRange(from: stringRep))
		#expect(original == roundTripped)
	}

	// MARK: - Helper property tests

	/// Verifies that isIPv4 and isIPv6 properties work correctly.
	///
	/// These convenience properties allow quick checking of address type
	/// without pattern matching.
	///
	/// Expected behavior:
	/// - IPv4 range should have isIPv4 = true, isIPv6 = false
	/// - IPv6 range should have isIPv4 = false, isIPv6 = true
	@Test("Address type properties work correctly")
	func addressTypeProperties() throws {
		let ipv4Range = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let ipv6Range = try #require(IPAddressRange(from: "2001:db8::/32"))

		#expect(ipv4Range.address.isIPv4 == true)
		#expect(ipv4Range.address.isIPv6 == false)

		#expect(ipv6Range.address.isIPv4 == false)
		#expect(ipv6Range.address.isIPv6 == true)
	}
}
