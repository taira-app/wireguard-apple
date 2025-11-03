import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for the DNSServer type.
///
/// These tests verify DNS server address parsing and formatting for both IPv4
/// and IPv6. DNS servers are configured on WireGuard interfaces to specify which
/// DNS resolvers should be used when the tunnel is active.
///
/// Test coverage includes:
/// - IPv4 DNS server parsing
/// - IPv6 DNS server parsing
/// - Invalid address rejection
/// - Equality and hashing
/// - String representation
struct DNSServerTests {
	// MARK: - IPv4 DNS server tests

	/// Verifies that IPv4 DNS server addresses can be parsed.
	///
	/// DNS servers are typically specified as plain IP addresses without ports.
	/// Common public DNS servers include Google (8.8.8.8) and Cloudflare (1.1.1.1).
	///
	/// Expected behavior:
	/// - Input "8.8.8.8" should parse successfully
	/// - Address should be recognized as IPv4
	/// - Parsed address should match input
	@Test("DNSServer parses IPv4 address")
	func parseIPv4Address() throws {
		let dnsString = "8.8.8.8"
		let dns = try #require(DNSServer(from: dnsString))

		if case .ipv4(let address) = dns.address {
			#expect(address.debugDescription == "8.8.8.8")
		} else {
			Issue.record("Expected IPv4 address")
		}
	}

	/// Verifies that IPv4 DNS servers format correctly as strings.
	///
	/// The string representation should match the input for IPv4 addresses.
	///
	/// Expected behavior:
	/// - DNS server created from "1.1.1.1" should format as "1.1.1.1"
	@Test("DNSServer formats IPv4 address correctly")
	func formatIPv4Address() throws {
		let dns = try #require(DNSServer(from: "1.1.1.1"))
		#expect(dns.stringRepresentation == "1.1.1.1")
	}

	/// Verifies that common public IPv4 DNS servers can be parsed.
	///
	/// Tests several well-known public DNS servers to ensure compatibility.
	/// These are commonly used in WireGuard configurations.
	///
	/// Expected behavior:
	/// - Google DNS, Cloudflare DNS, and Quad9 DNS should all parse successfully
	@Test("DNSServer accepts common public IPv4 DNS servers")
	func acceptCommonPublicIPv4DNS() throws {
		let publicDNS = [
			"8.8.8.8",  // Google DNS
			"1.1.1.1",  // Cloudflare DNS
			"9.9.9.9"  // Quad9 DNS
		]

		for dnsString in publicDNS {
			let dns = try #require(DNSServer(from: dnsString))

			if case .ipv4 = dns.address {
				// Success - verified it's IPv4
			} else {
				Issue.record("Expected IPv4 DNS for \(dnsString)")
			}
		}
	}

	// MARK: - IPv6 DNS server tests

	/// Verifies that IPv6 DNS server addresses can be parsed.
	///
	/// IPv6 DNS servers use standard IPv6 address notation, which may include
	/// compression with :: shorthand.
	///
	/// Expected behavior:
	/// - Input "2001:4860:4860::8888" should parse successfully
	/// - Address should be recognized as IPv6
	/// - Parsed address should match input
	@Test("DNSServer parses IPv6 address")
	func parseIPv6Address() throws {
		let dnsString = "2001:4860:4860::8888"
		let dns = try #require(DNSServer(from: dnsString))

		if case .ipv6(let address) = dns.address {
			#expect(address.debugDescription == "2001:4860:4860::8888")
		} else {
			Issue.record("Expected IPv6 address")
		}
	}

	/// Verifies that IPv6 DNS servers format correctly as strings.
	///
	/// The string representation should preserve IPv6 compressed notation.
	///
	/// Expected behavior:
	/// - DNS server created from "2606:4700:4700::1111" should format correctly
	/// - Compression (::) should be preserved
	@Test("DNSServer formats IPv6 address correctly")
	func formatIPv6Address() throws {
		let dns = try #require(DNSServer(from: "2606:4700:4700::1111"))

		if case .ipv6 = dns.address {
			// Verify it's IPv6
		} else {
			Issue.record("Expected IPv6 address")
		}

		#expect(dns.stringRepresentation.contains("2606:4700:4700"))
	}

	/// Verifies that common public IPv6 DNS servers can be parsed.
	///
	/// Tests several well-known public IPv6 DNS servers.
	///
	/// Expected behavior:
	/// - Google IPv6 DNS and Cloudflare IPv6 DNS should both parse successfully
	@Test("DNSServer accepts common public IPv6 DNS servers")
	func acceptCommonPublicIPv6DNS() throws {
		let publicDNS = [
			"2001:4860:4860::8888",  // Google DNS
			"2606:4700:4700::1111"  // Cloudflare DNS
		]

		for dnsString in publicDNS {
			let dns = try #require(DNSServer(from: dnsString))

			if case .ipv6 = dns.address {
				// Success - verified it's IPv6
			} else {
				Issue.record("Expected IPv6 DNS for \(dnsString)")
			}
		}
	}

	/// Verifies that fully expanded IPv6 addresses can be parsed.
	///
	/// IPv6 addresses can be written without compression for clarity.
	/// The parser must handle both compressed and expanded forms.
	///
	/// Expected behavior:
	/// - Fully expanded IPv6 address should parse successfully
	@Test("DNSServer parses fully expanded IPv6 address")
	func parseFullyExpandedIPv6() throws {
		let dnsString = "2001:0db8:0000:0000:0000:0000:0000:0001"
		let dns = try #require(DNSServer(from: dnsString))

		if case .ipv6 = dns.address {
			// Success - verified it's IPv6
		} else {
			Issue.record("Expected IPv6 address for fully expanded notation")
		}
	}

	// MARK: - Invalid address tests

	/// Verifies that invalid IP addresses are rejected.
	///
	/// Strings that cannot be parsed as either IPv4 or IPv6 should return nil.
	///
	/// Expected behavior:
	/// - Input "not.a.valid.ip" should return nil
	@Test("DNSServer rejects invalid IP address")
	func rejectInvalidIPAddress() throws {
		let invalidString = "not.a.valid.ip"
		let dns = DNSServer(from: invalidString)
		#expect(dns == nil)
	}

	/// Verifies that empty strings are rejected.
	///
	/// Empty strings are not valid IP addresses.
	///
	/// Expected behavior:
	/// - Input "" should return nil
	@Test("DNSServer rejects empty string")
	func rejectEmptyString() throws {
		let emptyString = ""
		let dns = DNSServer(from: emptyString)
		#expect(dns == nil)
	}

	/// Verifies that hostnames are rejected.
	///
	/// DNS server configurations require IP addresses, not hostnames.
	/// This prevents circular dependency issues (DNS needed to resolve DNS server).
	///
	/// Expected behavior:
	/// - Input "dns.google.com" should return nil
	@Test("DNSServer rejects hostname instead of IP")
	func rejectHostname() throws {
		let hostname = "dns.google.com"
		let dns = DNSServer(from: hostname)
		#expect(dns == nil)
	}

	/// Verifies that IP addresses with port numbers are rejected.
	///
	/// DNS server addresses should be plain IP addresses without ports.
	/// DNS uses port 53 by default and doesn't need explicit port specification.
	///
	/// Expected behavior:
	/// - Input "8.8.8.8:53" should return nil
	@Test("DNSServer rejects IP address with port")
	func rejectIPWithPort() throws {
		let withPort = "8.8.8.8:53"
		let dns = DNSServer(from: withPort)
		#expect(dns == nil)
	}

	// MARK: - Equality tests

	/// Verifies that a DNS server equals itself (reflexive property).
	///
	/// This tests the reflexive property of equality required by Equatable.
	///
	/// Expected behavior:
	/// - A DNS server compared to itself should be equal
	@Test("DNSServer equals itself")
	func dnsEqualsItself() throws {
		let dns = try #require(DNSServer(from: "8.8.8.8"))
		#expect(dns == dns)
	}

	/// Verifies that DNS servers with identical addresses are equal.
	///
	/// Two DNS servers created from the same IP address should be equal,
	/// demonstrating proper value semantics.
	///
	/// Expected behavior:
	/// - Two DNS servers from "8.8.8.8" should be equal
	@Test("DNSServers with same address are equal")
	func dnsWithSameAddressAreEqual() throws {
		let dns1 = try #require(DNSServer(from: "8.8.8.8"))
		let dns2 = try #require(DNSServer(from: "8.8.8.8"))
		#expect(dns1 == dns2)
	}

	/// Verifies that DNS servers with different addresses are not equal.
	///
	/// Different IP addresses represent different DNS servers.
	///
	/// Expected behavior:
	/// - DNS servers with IPs 8.8.8.8 and 1.1.1.1 should not be equal
	@Test("DNSServers with different addresses are not equal")
	func dnsWithDifferentAddressesNotEqual() throws {
		let dns1 = try #require(DNSServer(from: "8.8.8.8"))
		let dns2 = try #require(DNSServer(from: "1.1.1.1"))
		#expect(dns1 != dns2)
	}

	/// Verifies that IPv4 and IPv6 DNS servers are not equal.
	///
	/// Even if numerically similar, IPv4 and IPv6 are different address types.
	///
	/// Expected behavior:
	/// - IPv4 and IPv6 DNS servers should not be equal
	@Test("IPv4 and IPv6 DNS servers are not equal")
	func ipv4AndIPv6NotEqual() throws {
		let ipv4DNS = try #require(DNSServer(from: "8.8.8.8"))
		let ipv6DNS = try #require(DNSServer(from: "2001:4860:4860::8888"))
		#expect(ipv4DNS != ipv6DNS)
	}

	// MARK: - Hashing tests

	/// Verifies that DNS servers can be used in Sets.
	///
	/// Proper Hashable implementation is required for storing DNS servers in Sets.
	/// This is important as WireGuard configurations often have multiple DNS servers.
	///
	/// Expected behavior:
	/// - Two different DNS servers should both be stored in a Set
	/// - Set.contains() should work correctly
	@Test("DNSServer can be used in Set")
	func dnsCanBeUsedInSet() throws {
		let dns1 = try #require(DNSServer(from: "8.8.8.8"))
		let dns2 = try #require(DNSServer(from: "1.1.1.1"))

		var set = Set<DNSServer>()
		set.insert(dns1)
		set.insert(dns2)

		#expect(set.count == 2)
		#expect(set.contains(dns1))
		#expect(set.contains(dns2))
	}

	/// Verifies that duplicate DNS servers are deduplicated in Sets.
	///
	/// Adding the same DNS server multiple times should result in only one entry.
	///
	/// Expected behavior:
	/// - Adding the same DNS server twice should result in Set count of 1
	@Test("Duplicate DNS servers are deduplicated in Set")
	func duplicateDNSServersDeduplicatedInSet() throws {
		let dns1 = try #require(DNSServer(from: "8.8.8.8"))
		let dns2 = try #require(DNSServer(from: "8.8.8.8"))

		var set = Set<DNSServer>()
		set.insert(dns1)
		set.insert(dns2)

		#expect(set.count == 1)
	}

	// MARK: - Helper property tests

	/// Verifies that isIPv4 and isIPv6 properties work correctly.
	///
	/// These convenience properties allow quick checking of address type.
	///
	/// Expected behavior:
	/// - IPv4 DNS should have isIPv4 = true, isIPv6 = false
	/// - IPv6 DNS should have isIPv4 = false, isIPv6 = true
	@Test("Address type properties work correctly")
	func addressTypeProperties() throws {
		let ipv4DNS = try #require(DNSServer(from: "8.8.8.8"))
		let ipv6DNS = try #require(DNSServer(from: "2001:4860:4860::8888"))

		#expect(ipv4DNS.address.isIPv4 == true)
		#expect(ipv4DNS.address.isIPv6 == false)

		#expect(ipv6DNS.address.isIPv4 == false)
		#expect(ipv6DNS.address.isIPv6 == true)
	}
}
