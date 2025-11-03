import Testing

@testable import WireGuard

/// Tests for IntegrationError error descriptions.
///
/// These tests verify that error messages are clear and helpful for developers.
/// Good error messages help developers quickly understand what went wrong and how to fix it.
@Suite("Integration error description tests")
struct IntegrationErrorDescriptionTests {

	// MARK: - IPv4 address errors

	/// Test that the noIPv4Address error has a clear, understandable description.
	///
	/// The error description is what developers see when this error occurs.
	/// It should clearly explain that the configuration is missing an IPv4 address.
	@Test("NoIPv4Address error has clear description")
	func testNoIPv4AddressDescription() {
		// Create the error that occurs when no IPv4 address is configured.
		let error = IntegrationError.noIPv4Address

		// Verify the error description mentions "IPv4" so developers know what's missing.
		#expect(error.errorDescription?.contains("IPv4") == true)

		// Verify the error description mentions "address" so the problem is clear.
		#expect(error.errorDescription?.contains("address") == true)
	}

	/// Test that the noIPv4Address error suggests how to fix the problem.
	///
	/// Recovery suggestions tell developers what action they should take to resolve the error.
	/// This is important for helping newcomers fix configuration problems quickly.
	@Test("NoIPv4Address error has helpful recovery suggestion")
	func testNoIPv4AddressRecoverySuggestion() {
		// Create the error.
		let error = IntegrationError.noIPv4Address

		// Verify a recovery suggestion is provided (not nil).
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion mentions adding an address to the configuration.
		#expect(error.recoverySuggestion?.contains("address") == true)
	}

	/// Test that the noIPv4Address error explains the technical reason for the failure.
	///
	/// The failure reason provides more technical context about why this is an error.
	/// This helps developers understand the underlying cause.
	@Test("NoIPv4Address error has detailed failure reason")
	func testNoIPv4AddressFailureReason() {
		// Create the error.
		let error = IntegrationError.noIPv4Address

		// Verify a failure reason is provided.
		#expect(error.failureReason != nil)

		// Verify the reason mentions IPv4 to identify the specific issue.
		#expect(error.failureReason?.contains("IPv4") == true)
	}

	// MARK: - IPv6 address errors

	/// Test that the noIPv6Address error has a clear description.
	///
	/// Similar to IPv4, this error should clearly explain that an IPv6 address is missing.
	@Test("NoIPv6Address error has clear description")
	func testNoIPv6AddressDescription() {
		// Create the error that occurs when no IPv6 address is configured.
		let error = IntegrationError.noIPv6Address

		// Verify the error description mentions "IPv6".
		#expect(error.errorDescription?.contains("IPv6") == true)

		// Verify the error description mentions "address".
		#expect(error.errorDescription?.contains("address") == true)
	}

	/// Test that the noIPv6Address error provides a recovery suggestion.
	@Test("NoIPv6Address error has helpful recovery suggestion")
	func testNoIPv6AddressRecoverySuggestion() {
		// Create the error.
		let error = IntegrationError.noIPv6Address

		// Verify a recovery suggestion exists.
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion helps developers fix the IPv6 configuration.
		#expect(error.recoverySuggestion?.contains("address") == true)
	}

	/// Test that the noIPv6Address error explains why it failed.
	@Test("NoIPv6Address error has detailed failure reason")
	func testNoIPv6AddressFailureReason() {
		// Create the error.
		let error = IntegrationError.noIPv6Address

		// Verify a failure reason is provided.
		#expect(error.failureReason != nil)

		// Verify it mentions IPv6 specifically.
		#expect(error.failureReason?.contains("IPv6") == true)
	}

	// MARK: - Route validation errors

	/// Test that invalidRoute error includes the problematic route in the description.
	///
	/// When a route is invalid, showing the actual route string helps developers
	/// identify exactly which route in their configuration is causing the problem.
	@Test("InvalidRoute error includes route information in description")
	func testInvalidRouteDescription() {
		// Create an error for a specific invalid route.
		// This simulates what happens when a developer provides a malformed CIDR.
		let error = IntegrationError.invalidRoute("10.0.0.0/8")

		// Verify the error shows the exact route that was invalid.
		#expect(error.errorDescription?.contains("10.0.0.0/8") == true)

		// Verify the error mentions it's a route problem.
		#expect(error.errorDescription?.contains("route") == true)
	}

	/// Test that invalidRoute error suggests how to fix the route format.
	///
	/// Newcomers may not be familiar with CIDR notation, so the recovery suggestion
	/// should guide them toward the correct format.
	@Test("InvalidRoute error has helpful recovery suggestion")
	func testInvalidRouteRecoverySuggestion() {
		// Create an error with an obviously invalid route.
		let error = IntegrationError.invalidRoute("invalid")

		// Verify a recovery suggestion exists.
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion mentions CIDR format or general format guidance.
		// Either term helps developers understand the expected format.
		#expect(
			error.recoverySuggestion?.contains("CIDR") == true
				|| error.recoverySuggestion?.contains("format") == true
		)
	}

	// MARK: - DNS validation errors

	/// Test that invalidDNS error shows the problematic DNS server in the description.
	///
	/// Similar to routes, showing the exact DNS value that failed helps developers
	/// identify which DNS server in their configuration needs to be fixed.
	@Test("InvalidDNS error includes DNS information in description")
	func testInvalidDNSDescription() {
		// Create an error for an invalid DNS server.
		// This happens when a developer provides a hostname instead of an IP address.
		let error = IntegrationError.invalidDNS("not.an.ip")

		// Verify the error shows the exact DNS value that was invalid.
		#expect(error.errorDescription?.contains("not.an.ip") == true)

		// Verify the error identifies it as a DNS problem.
		#expect(error.errorDescription?.contains("DNS") == true)
	}

	/// Test that invalidDNS error suggests using a valid IP address.
	///
	/// DNS servers must be IP addresses, not hostnames. The recovery suggestion
	/// should make this clear to developers.
	@Test("InvalidDNS error has helpful recovery suggestion")
	func testInvalidDNSRecoverySuggestion() {
		// Create an error with an invalid DNS value.
		let error = IntegrationError.invalidDNS("invalid")

		// Verify a recovery suggestion exists.
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion mentions using an IP address.
		#expect(
			error.recoverySuggestion?.contains("IP") == true
				|| error.recoverySuggestion?.contains("address") == true
		)
	}

	// MARK: - Settings generation errors

	/// Test that settingsGenerationFailed error includes the specific reason.
	///
	/// Settings generation can fail for many reasons. Including the specific reason
	/// helps developers understand what part of their configuration is problematic.
	@Test("SettingsGenerationFailed error includes reason in description")
	func testSettingsGenerationFailedDescription() {
		// Create an error with a specific failure reason.
		// This simulates a configuration that has no peers defined.
		let error = IntegrationError.settingsGenerationFailed("no peers configured")

		// Verify the error shows the specific reason for failure.
		#expect(error.errorDescription?.contains("no peers configured") == true)

		// Verify the error identifies it as a settings generation problem.
		#expect(error.errorDescription?.contains("settings") == true)
	}

	/// Test that settingsGenerationFailed error suggests checking the configuration.
	///
	/// Since this error can occur for various configuration problems, the recovery
	/// suggestion should guide developers to review their configuration.
	@Test("SettingsGenerationFailed error has helpful recovery suggestion")
	func testSettingsGenerationFailedRecoverySuggestion() {
		// Create an error with a generic failure reason.
		let error = IntegrationError.settingsGenerationFailed("missing data")

		// Verify a recovery suggestion exists.
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion mentions checking the configuration.
		#expect(error.recoverySuggestion?.contains("configuration") == true)
	}

	// MARK: - Packet flow errors

	/// Test that packetFlowError error includes the problem details.
	///
	/// Packet flow errors occur during runtime when communicating with the tunnel.
	/// Including the error details helps developers debug connection issues.
	@Test("PacketFlowError error includes details in description")
	func testPacketFlowErrorDescription() {
		// Create an error for a packet flow problem.
		// This simulates what happens when the connection is unexpectedly closed.
		let error = IntegrationError.packetFlowError("connection closed")

		// Verify the error shows the specific problem that occurred.
		#expect(error.errorDescription?.contains("connection closed") == true)

		// Verify the error identifies it as a packet flow problem.
		#expect(error.errorDescription?.contains("packet") == true)
	}

	/// Test that packetFlowError error suggests how to recover.
	///
	/// Packet flow errors often require reconnecting or restarting the tunnel.
	/// The recovery suggestion should guide developers toward appropriate actions.
	@Test("PacketFlowError error has helpful recovery suggestion")
	func testPacketFlowErrorRecoverySuggestion() {
		// Create an error for a timeout scenario.
		let error = IntegrationError.packetFlowError("timeout")

		// Verify a recovery suggestion exists.
		#expect(error.recoverySuggestion != nil)

		// Verify the suggestion mentions reconnecting the tunnel or checking the connection.
		#expect(
			error.recoverySuggestion?.contains("tunnel") == true
				|| error.recoverySuggestion?.contains("connection") == true
		)
	}
}
