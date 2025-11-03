import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for Endpoint validation, equality, and hashing.
///
/// These tests verify that endpoints correctly reject invalid input formats
/// and properly implement Equatable and Hashable protocols. Endpoints are critical
/// for WireGuard as they specify where encrypted packets should be sent.
///
/// Test coverage includes:
/// - Invalid format rejection
/// - Equality and hashing
/// - Edge cases and error handling
///
/// See also: EndpointParsingTests.swift for successful parsing scenarios.
struct EndpointValidationTests {
	// MARK: - Invalid format tests

	/// Verifies that endpoints without ports are rejected.
	///
	/// WireGuard requires explicit port numbers - there is no default port.
	/// Accepting hostnames without ports would lead to ambiguous configurations.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1" (no port) should return nil
	/// - Parser should not assume a default port
	@Test("Endpoint rejects missing port")
	func rejectMissingPort() throws {
		let invalidString = "192.168.1.1"
		let endpoint = Endpoint(from: invalidString)
		#expect(endpoint == nil)
	}

	/// Verifies that endpoints with empty port strings are rejected.
	///
	/// A trailing colon with no port number is invalid syntax and should not
	/// be accepted even with lenient parsing.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:" should return nil
	@Test("Endpoint rejects empty port")
	func rejectEmptyPort() throws {
		let invalidString = "192.168.1.1:"
		let endpoint = Endpoint(from: invalidString)
		#expect(endpoint == nil)
	}

	/// Verifies that port 0 is rejected.
	///
	/// Port 0 is reserved in the TCP/IP stack and cannot be used for WireGuard.
	/// Only ports 1-65535 are valid.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:0" should return nil
	@Test("Endpoint rejects zero port")
	func rejectZeroPort() throws {
		let invalidString = "192.168.1.1:0"
		let endpoint = Endpoint(from: invalidString)
		#expect(endpoint == nil)
	}

	/// Verifies that port numbers exceeding UInt16 range are rejected.
	///
	/// Port numbers are limited to 16-bit unsigned integers (1-65535).
	/// Values outside this range should cause parsing to fail.
	///
	/// Expected behavior:
	/// - Input "192.168.1.1:99999" should return nil
	/// - Parser should validate port range
	@Test("Endpoint rejects invalid port number")
	func rejectInvalidPort() throws {
		let invalidString = "192.168.1.1:99999"
		let endpoint = Endpoint(from: invalidString)
		#expect(endpoint == nil)
	}

	/// Verifies that IPv6 addresses without brackets are handled correctly.
	///
	/// IPv6 addresses without brackets create ambiguity because their colons
	/// cannot be distinguished from the port separator. The parser should either
	/// reject these or interpret them as hostnames (not IPv6).
	///
	/// Expected behavior:
	/// - Input "2001:db8::1:51820" should NOT parse as IPv6 endpoint
	/// - May return nil or parse as hostname (both acceptable)
	/// - Must not incorrectly parse as IPv6
	@Test("Endpoint rejects IPv6 without brackets")
	func rejectIPv6WithoutBrackets() throws {
		let ambiguousString = "2001:db8::1:51820"
		let endpoint = Endpoint(from: ambiguousString)

		if let ep = endpoint {
			if case .name = ep.host {
				// OK - parsed as hostname due to ambiguity
			} else {
				Issue.record("IPv6 without brackets should not parse as IPv6 endpoint")
			}
		}
		// Also OK to return nil
	}

	/// Verifies that malformed IPv6 bracket notation is rejected.
	///
	/// If an IPv6 address starts with a bracket but doesn't close it,
	/// this is a syntax error and must be rejected.
	///
	/// Expected behavior:
	/// - Input "[2001:db8::1:51820" (unclosed bracket) should return nil
	@Test("Endpoint rejects malformed IPv6 brackets")
	func rejectMalformedIPv6Brackets() throws {
		let malformedString = "[2001:db8::1:51820"
		let endpoint = Endpoint(from: malformedString)
		#expect(endpoint == nil)
	}

	/// Verifies that IPv6 addresses in brackets but missing port colon are rejected.
	///
	/// Even with brackets present, the colon before the port is required.
	/// "[::1]51820" is invalid - it must be "[::1]:51820".
	///
	/// Expected behavior:
	/// - Input "[::1]51820" should return nil
	@Test("Endpoint rejects missing colon before port")
	func rejectMissingColon() throws {
		let invalidString = "[::1]51820"
		let endpoint = Endpoint(from: invalidString)
		#expect(endpoint == nil)
	}

	// MARK: - Equality tests

	/// Verifies that an endpoint equals itself (reflexive property).
	///
	/// This tests the reflexive property of equality: a == a must always be true.
	/// This is a fundamental requirement for Equatable conformance.
	///
	/// Expected behavior:
	/// - An endpoint compared to itself should be equal
	@Test("Endpoint equals itself")
	func endpointEqualsItself() throws {
		let endpoint = try #require(Endpoint(from: "192.168.1.1:51820"))
		#expect(endpoint == endpoint)
	}

	/// Verifies that endpoints with identical data are equal (value semantics).
	///
	/// Since Endpoint is a value type (struct), two instances with the same
	/// host and port should be equal. This tests proper value semantics.
	///
	/// Expected behavior:
	/// - Two endpoints created from "192.168.1.1:51820" should be equal
	/// - Symmetric property: endpoint1 == endpoint2 implies endpoint2 == endpoint1
	@Test("Endpoints with same data are equal")
	func endpointsWithSameDataAreEqual() throws {
		let endpoint1 = try #require(Endpoint(from: "192.168.1.1:51820"))
		let endpoint2 = try #require(Endpoint(from: "192.168.1.1:51820"))
		#expect(endpoint1 == endpoint2)
	}

	/// Verifies that endpoints with different ports are not equal.
	///
	/// Different ports represent different services or instances, so endpoints
	/// with the same host but different ports must not be equal.
	///
	/// Expected behavior:
	/// - Endpoints with ports 51820 and 8080 should not be equal
	@Test("Endpoints with different ports are not equal")
	func endpointsWithDifferentPortsNotEqual() throws {
		let endpoint1 = try #require(Endpoint(from: "192.168.1.1:51820"))
		let endpoint2 = try #require(Endpoint(from: "192.168.1.1:8080"))
		#expect(endpoint1 != endpoint2)
	}

	/// Verifies that endpoints with different hosts are not equal.
	///
	/// Different hosts represent different machines, so endpoints with different
	/// hosts must not be equal even if they have the same port.
	///
	/// Expected behavior:
	/// - Endpoints with IPs 192.168.1.1 and 192.168.1.2 should not be equal
	@Test("Endpoints with different hosts are not equal")
	func endpointsWithDifferentHostsNotEqual() throws {
		let endpoint1 = try #require(Endpoint(from: "192.168.1.1:51820"))
		let endpoint2 = try #require(Endpoint(from: "192.168.1.2:51820"))
		#expect(endpoint1 != endpoint2)
	}

	// MARK: - Hashing tests

	/// Verifies that endpoints can be used in Sets (Hashable conformance).
	///
	/// Proper Hashable implementation is required for using endpoints in Sets
	/// and as Dictionary keys. This tests that equal endpoints have equal hashes
	/// and that different endpoints can coexist in a Set.
	///
	/// Expected behavior:
	/// - Two different endpoints should both be stored in a Set
	/// - Set.contains() should work correctly
	/// - Set count should reflect actual unique endpoints
	@Test("Endpoint can be used in Set")
	func endpointCanBeUsedInSet() throws {
		let endpoint1 = try #require(Endpoint(from: "192.168.1.1:51820"))
		let endpoint2 = try #require(Endpoint(from: "192.168.1.2:51820"))

		var set = Set<Endpoint>()
		set.insert(endpoint1)
		set.insert(endpoint2)

		#expect(set.count == 2)
		#expect(set.contains(endpoint1))
		#expect(set.contains(endpoint2))
	}
}
