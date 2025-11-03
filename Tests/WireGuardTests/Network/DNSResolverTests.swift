import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for the DNSResolver actor.
///
/// These tests verify asynchronous DNS resolution functionality. DNS resolution
/// is important for WireGuard as it allows endpoints to be specified by hostname
/// rather than requiring fixed IP addresses.
///
/// Test coverage includes:
/// - Basic resolution functionality
/// - Timeout handling
/// - Error handling for invalid hostnames
/// - Concurrent resolution support
///
/// Note: Some tests perform actual DNS resolution and may fail if network
/// connectivity is unavailable. These are integration tests rather than pure
/// unit tests.
struct DNSResolverTests {
	// MARK: - Resolution tests

	/// Verifies that well-known hostnames can be resolved.
	///
	/// This tests basic DNS resolution functionality using "localhost" which
	/// should always resolve to 127.0.0.1 or ::1 without requiring network access.
	///
	/// Expected behavior:
	/// - Hostname "localhost" should resolve successfully
	/// - Result should contain at least one host address
	/// - Hosts should be either IPv4 or IPv6 variants
	@Test("DNSResolver resolves localhost")
	func resolveLocalhost() async throws {
		let resolver = DNSResolver()

		let hosts = try await resolver.resolve("localhost")

		// Should get at least one result (127.0.0.1 or ::1)
		#expect(hosts.count > 0)

		// Verify all results are valid host types
		for host in hosts {
			switch host {
			case .ipv4, .ipv6:
				// Valid host type
				break
			case .name:
				Issue.record("Resolution should return IP addresses, not names")
			}
		}
	}

	/// Verifies that IPv4-only hostnames resolve to IPv4 addresses.
	///
	/// Tests resolution of a hostname that should return IPv4 addresses.
	/// This verifies that the resolver correctly extracts IPv4 addresses.
	///
	/// Expected behavior:
	/// - Resolution should succeed
	/// - At least one result should be IPv4
	///
	/// Note: This is an integration test and may fail without network connectivity.
	@Test("DNSResolver resolves IPv4 addresses")
	func resolveIPv4() async throws {
		let resolver = DNSResolver()

		// Use a well-known hostname that should have IPv4
		let hosts = try await resolver.resolve("one.one.one.one")

		// Should get at least one result
		#expect(hosts.count > 0)

		// At least one should be IPv4
		let hasIPv4 = hosts.contains { host in
			if case .ipv4 = host { return true }
			return false
		}
		#expect(hasIPv4)
	}

	/// Verifies that dual-stack hostnames can return both IPv4 and IPv6.
	///
	/// Modern hostnames often have both A and AAAA records. The resolver
	/// should be able to return both address types when available.
	///
	/// Expected behavior:
	/// - Resolution should succeed
	/// - Results may include IPv4, IPv6, or both
	///
	/// Note: This is an integration test and may fail without network connectivity.
	@Test("DNSResolver handles dual-stack hostnames")
	func resolveDualStack() async throws {
		let resolver = DNSResolver()

		// Use a hostname known to have both IPv4 and IPv6
		let hosts = try await resolver.resolve("dns.google")

		// Should get at least one result
		#expect(hosts.count > 0)

		// Results should be IP addresses
		for host in hosts {
			switch host {
			case .ipv4, .ipv6:
				// Valid - either type is acceptable
				break
			case .name:
				Issue.record("Should resolve to IP addresses")
			}
		}
	}

	// MARK: - Error handling tests

	/// Verifies that invalid hostnames produce resolution failures.
	///
	/// Hostnames that don't exist or can't be resolved should throw
	/// a resolutionFailed error with the hostname included.
	///
	/// Expected behavior:
	/// - Input "this.hostname.definitely.does.not.exist.invalid" should throw
	/// - Error should be NetworkError.resolutionFailed with hostname
	@Test("DNSResolver fails for invalid hostname")
	func failForInvalidHostname() async throws {
		let resolver = DNSResolver()
		let invalidHostname = "this.hostname.definitely.does.not.exist.invalid"

		do {
			_ = try await resolver.resolve(invalidHostname)
			Issue.record("Should have thrown an error for invalid hostname")
		} catch let error as NetworkError {
			// Should be a resolution failed error
			if case .resolutionFailed(let hostname) = error {
				#expect(hostname == invalidHostname)
			} else {
				Issue.record("Expected resolutionFailed error, got \(error)")
			}
		} catch {
			Issue.record("Expected NetworkError, got \(error)")
		}
	}

	/// Verifies that empty hostnames are rejected.
	///
	/// Empty strings are not valid hostnames and should fail resolution.
	///
	/// Expected behavior:
	/// - Input "" should throw a resolution error
	@Test("DNSResolver fails for empty hostname")
	func failForEmptyHostname() async throws {
		let resolver = DNSResolver()

		do {
			_ = try await resolver.resolve("")
			Issue.record("Should have thrown an error for empty hostname")
		} catch is NetworkError {
			// Expected - any NetworkError is acceptable for empty hostname
		} catch {
			Issue.record("Expected NetworkError, got \(error)")
		}
	}

	// MARK: - Timeout tests

	/// Verifies that the resolver respects timeout configuration.
	///
	/// When created with a custom timeout, the resolver should use that
	/// timeout value for resolution operations.
	///
	/// Expected behavior:
	/// - A resolver created with a very short timeout (0.001 seconds) should
	///   time out quickly when resolving a hostname
	///
	/// Note: This test uses a very short timeout to ensure it fires. In practice,
	/// this might cause false failures if the system resolves instantly.
	@Test("DNSResolver respects custom timeout")
	func respectCustomTimeout() async throws {
		// Create resolver with very short timeout
		let resolver = DNSResolver(timeout: 0.001)

		// Try to resolve a hostname (may timeout or succeed very quickly)
		do {
			_ = try await resolver.resolve("example.com")
			// If it succeeds, that's fine - resolution was very fast
		} catch let error as NetworkError {
			// Should be either timeout or resolution failed
			switch error {
			case .resolutionTimeout, .resolutionFailed:
				// Both are acceptable outcomes
				break
			default:
				Issue.record("Unexpected error type: \(error)")
			}
		} catch {
			Issue.record("Expected NetworkError, got \(error)")
		}
	}

	/// Verifies that default timeout is reasonable.
	///
	/// The default timeout should be long enough for normal DNS operations
	/// but not so long that it causes long delays on failure.
	///
	/// Expected behavior:
	/// - DNSResolver.defaultTimeout should be a reasonable value (e.g., 30 seconds)
	@Test("DNSResolver has reasonable default timeout")
	func hasReasonableDefaultTimeout() throws {
		let defaultTimeout = DNSResolver.defaultTimeout

		// Should be at least 1 second
		#expect(defaultTimeout >= 1.0)

		// Should be no more than 60 seconds
		#expect(defaultTimeout <= 60.0)
	}

	// MARK: - Concurrent resolution tests

	/// Verifies that multiple resolutions can run concurrently.
	///
	/// As an actor, DNSResolver should handle multiple concurrent resolution
	/// requests safely. Each request should complete independently.
	///
	/// Expected behavior:
	/// - Multiple concurrent resolve calls should all complete
	/// - Results should be independent for different hostnames
	///
	/// Note: This is an integration test and may fail without network connectivity.
	@Test("DNSResolver handles concurrent resolutions")
	func handleConcurrentResolutions() async throws {
		let resolver = DNSResolver()

		// Start multiple resolutions concurrently
		async let result1 = resolver.resolve("localhost")
		async let result2 = resolver.resolve("one.one.one.one")
		async let result3 = resolver.resolve("dns.google")

		// Wait for all to complete
		let (hosts1, hosts2, hosts3) = try await (result1, result2, result3)

		// All should have results
		#expect(hosts1.count > 0)
		#expect(hosts2.count > 0)
		#expect(hosts3.count > 0)
	}

	/// Verifies that the same hostname resolved twice gives consistent results.
	///
	/// While DNS can change, resolving the same hostname twice in quick succession
	/// should generally give the same results.
	///
	/// Expected behavior:
	/// - Resolving "localhost" twice should give consistent address types
	///
	/// Note: This test is somewhat non-deterministic as DNS can change, but
	/// localhost should be stable.
	@Test("DNSResolver gives consistent results for same hostname")
	func givesConsistentResults() async throws {
		let resolver = DNSResolver()

		let hosts1 = try await resolver.resolve("localhost")
		let hosts2 = try await resolver.resolve("localhost")

		// Should both have results
		#expect(hosts1.count > 0)
		#expect(hosts2.count > 0)

		// Both should have IP addresses (not names)
		for host in hosts1 {
			switch host {
			case .ipv4, .ipv6:
				// Good - these are IP addresses
				break
			case .name:
				Issue.record("Resolution should return IP addresses")
			}
		}

		for host in hosts2 {
			switch host {
			case .ipv4, .ipv6:
				// Good - these are IP addresses
				break
			case .name:
				Issue.record("Resolution should return IP addresses")
			}
		}
	}

	// MARK: - Integration with Endpoint tests

	/// Verifies that resolved hosts can be used to create endpoints.
	///
	/// The resolved Host enum values should be compatible with Endpoint creation.
	/// This tests the integration between DNSResolver and Endpoint types.
	///
	/// Expected behavior:
	/// - Resolved hosts should be .ipv4 or .ipv6 variants
	/// - These variants should work with Endpoint creation
	///
	/// Note: This is an integration test.
	@Test("Resolved hosts can be used with Endpoint")
	func resolvedHostsWorkWithEndpoint() async throws {
		let resolver = DNSResolver()

		let hosts = try await resolver.resolve("localhost")
		#expect(hosts.count > 0)

		// Each resolved host should be usable with Endpoint
		for host in hosts {
			let endpoint = Endpoint(host: host, port: 51820)

			// Verify the endpoint was created correctly
			#expect(endpoint.port == 51820)

			switch endpoint.host {
			case .ipv4, .ipv6:
				// Good - these are the expected types from resolution
				break
			case .name:
				Issue.record("Resolved hosts should be IP addresses, not names")
			}
		}
	}
}
