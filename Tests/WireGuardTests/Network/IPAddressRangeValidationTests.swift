import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for IPAddressRange validation, equality, and hashing.
///
/// These tests verify that IP address ranges correctly reject invalid input formats
/// and properly implement Equatable and Hashable protocols. IP address ranges are
/// used in WireGuard for allowed IPs and interface addresses.
///
/// Test coverage includes:
/// - Invalid format rejection
/// - Prefix length validation
/// - Equality and hashing
/// - Edge cases and error handling
///
/// See also: IPAddressRangeParsingTests.swift for successful parsing scenarios.
struct IPAddressRangeValidationTests {
	// MARK: - Invalid format tests

	/// Verifies that CIDR notation without slash is rejected.
	///
	/// CIDR notation requires both an address and a prefix length separated by /.
	/// IP addresses without prefixes are incomplete and must be rejected.
	///
	/// Expected behavior:
	/// - Input "192.168.1.0" (no prefix) should return nil
	@Test("IPAddressRange rejects CIDR without slash")
	func rejectCIDRWithoutSlash() throws {
		let invalidString = "192.168.1.0"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	/// Verifies that CIDR notation with empty prefix is rejected.
	///
	/// A trailing slash with no prefix length is invalid syntax.
	///
	/// Expected behavior:
	/// - Input "192.168.1.0/" should return nil
	@Test("IPAddressRange rejects empty prefix")
	func rejectEmptyPrefix() throws {
		let invalidString = "192.168.1.0/"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	/// Verifies that IPv4 addresses with prefix > 32 are rejected.
	///
	/// IPv4 addresses have 32 bits, so prefix lengths > 32 are invalid.
	/// This tests boundary validation for IPv4.
	///
	/// Expected behavior:
	/// - Input "192.168.1.0/33" should return nil
	/// - Prefix validation should enforce 0-32 range for IPv4
	@Test("IPAddressRange rejects IPv4 prefix greater than 32")
	func rejectIPv4PrefixTooLarge() throws {
		let invalidString = "192.168.1.0/33"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	/// Verifies that IPv6 addresses with prefix > 128 are rejected.
	///
	/// IPv6 addresses have 128 bits, so prefix lengths > 128 are invalid.
	/// This tests boundary validation for IPv6.
	///
	/// Expected behavior:
	/// - Input "2001:db8::/129" should return nil
	/// - Prefix validation should enforce 0-128 range for IPv6
	@Test("IPAddressRange rejects IPv6 prefix greater than 128")
	func rejectIPv6PrefixTooLarge() throws {
		let invalidString = "2001:db8::/129"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	/// Verifies that non-numeric prefix values are rejected.
	///
	/// Prefix lengths must be decimal integers, not other formats.
	///
	/// Expected behavior:
	/// - Input "192.168.1.0/abc" should return nil
	@Test("IPAddressRange rejects non-numeric prefix")
	func rejectNonNumericPrefix() throws {
		let invalidString = "192.168.1.0/abc"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	/// Verifies that invalid IP addresses are rejected.
	///
	/// If the address portion of the CIDR string cannot be parsed as an IP address,
	/// the entire CIDR string should be rejected.
	///
	/// Expected behavior:
	/// - Input "not.an.ip/24" should return nil
	@Test("IPAddressRange rejects invalid IP address")
	func rejectInvalidIPAddress() throws {
		let invalidString = "not.an.ip/24"
		let range = IPAddressRange(from: invalidString)
		#expect(range == nil)
	}

	// MARK: - Equality tests

	/// Verifies that an IP address range equals itself (reflexive property).
	///
	/// This tests the reflexive property of equality required by Equatable.
	///
	/// Expected behavior:
	/// - A range compared to itself should be equal
	@Test("IPAddressRange equals itself")
	func rangeEqualsItself() throws {
		let range = try #require(IPAddressRange(from: "192.168.1.0/24"))
		#expect(range == range)
	}

	/// Verifies that ranges with identical data are equal.
	///
	/// Two ranges created from the same CIDR string should be equal,
	/// demonstrating proper value semantics.
	///
	/// Expected behavior:
	/// - Two ranges from "192.168.1.0/24" should be equal
	@Test("IPAddressRanges with same data are equal")
	func rangesWithSameDataAreEqual() throws {
		let range1 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let range2 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		#expect(range1 == range2)
	}

	/// Verifies that ranges with different addresses are not equal.
	///
	/// Different network addresses represent different subnets,
	/// so they must not be equal.
	///
	/// Expected behavior:
	/// - Ranges 192.168.1.0/24 and 192.168.2.0/24 should not be equal
	@Test("IPAddressRanges with different addresses are not equal")
	func rangesWithDifferentAddressesNotEqual() throws {
		let range1 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let range2 = try #require(IPAddressRange(from: "192.168.2.0/24"))
		#expect(range1 != range2)
	}

	/// Verifies that ranges with different prefix lengths are not equal.
	///
	/// Different prefix lengths represent different subnet sizes,
	/// so they must not be equal even with the same base address.
	///
	/// Expected behavior:
	/// - Ranges 192.168.1.0/24 and 192.168.1.0/25 should not be equal
	@Test("IPAddressRanges with different prefixes are not equal")
	func rangesWithDifferentPrefixesNotEqual() throws {
		let range1 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let range2 = try #require(IPAddressRange(from: "192.168.1.0/25"))
		#expect(range1 != range2)
	}

	// MARK: - Hashing tests

	/// Verifies that IP address ranges can be used in Sets.
	///
	/// Proper Hashable implementation is required for using ranges in Sets
	/// and as Dictionary keys. This is important for WireGuard as allowed IPs
	/// are often stored in collections.
	///
	/// Expected behavior:
	/// - Two different ranges should both be stored in a Set
	/// - Set.contains() should work correctly
	@Test("IPAddressRange can be used in Set")
	func rangeCanBeUsedInSet() throws {
		let range1 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let range2 = try #require(IPAddressRange(from: "10.0.0.0/8"))

		var set = Set<IPAddressRange>()
		set.insert(range1)
		set.insert(range2)

		#expect(set.count == 2)
		#expect(set.contains(range1))
		#expect(set.contains(range2))
	}
}
