import Testing

@testable import WireGuard

/// Tests for IntegrationError equality comparisons.
///
/// Errors need to conform to Equatable so they can be compared in tests and application logic.
/// These tests verify that errors with the same type and data are considered equal,
/// while different errors are correctly identified as not equal.
@Suite("Integration error equality tests")
struct IntegrationErrorEqualityTests {

	// MARK: - Same error type equality

	/// Test that two noIPv4Address errors are equal.
	///
	/// Errors without associated data (like noIPv4Address) should always be equal
	/// to other instances of the same error type.
	@Test("NoIPv4Address errors are equal")
	func testNoIPv4AddressEquality() {
		// Create two instances of the same error type.
		let error1 = IntegrationError.noIPv4Address
		let error2 = IntegrationError.noIPv4Address

		// Verify they are considered equal.
		// This is important for error handling logic that compares errors.
		#expect(error1 == error2)
	}

	/// Test that two noIPv6Address errors are equal.
	///
	/// Like noIPv4Address, this error type has no associated data,
	/// so all instances should be equal.
	@Test("NoIPv6Address errors are equal")
	func testNoIPv6AddressEquality() {
		// Create two instances of the same error type.
		let error1 = IntegrationError.noIPv6Address
		let error2 = IntegrationError.noIPv6Address

		// Verify they are equal.
		#expect(error1 == error2)
	}

	// MARK: - Error with associated data equality

	/// Test that invalidRoute errors with the same route string are equal.
	///
	/// Errors with associated data (like the route string) should be equal
	/// when both the error type and the associated data match.
	@Test("InvalidRoute errors with same route are equal")
	func testInvalidRouteEqualitySame() {
		// Create two errors for the same invalid route.
		// Both errors have the same type (invalidRoute) and same data ("10.0.0.0/8").
		let error1 = IntegrationError.invalidRoute("10.0.0.0/8")
		let error2 = IntegrationError.invalidRoute("10.0.0.0/8")

		// Verify they are considered equal.
		#expect(error1 == error2)
	}

	/// Test that invalidRoute errors with different route strings are not equal.
	///
	/// Even though these are both invalidRoute errors, they have different associated data,
	/// so they should not be considered equal.
	@Test("InvalidRoute errors with different routes are not equal")
	func testInvalidRouteEqualityDifferent() {
		// Create two errors for different invalid routes.
		// The error type is the same, but the associated data differs.
		let error1 = IntegrationError.invalidRoute("10.0.0.0/8")
		let error2 = IntegrationError.invalidRoute("192.168.0.0/16")

		// Verify they are not equal because the route strings differ.
		#expect(error1 != error2)
	}

	/// Test that invalidDNS errors with the same DNS string are equal.
	@Test("InvalidDNS errors with same DNS are equal")
	func testInvalidDNSEqualitySame() {
		// Create two errors for the same invalid DNS value.
		let error1 = IntegrationError.invalidDNS("not.valid")
		let error2 = IntegrationError.invalidDNS("not.valid")

		// Verify they are equal since both type and data match.
		#expect(error1 == error2)
	}

	/// Test that invalidDNS errors with different DNS strings are not equal.
	@Test("InvalidDNS errors with different DNS are not equal")
	func testInvalidDNSEqualityDifferent() {
		// Create two errors for different invalid DNS values.
		let error1 = IntegrationError.invalidDNS("first")
		let error2 = IntegrationError.invalidDNS("second")

		// Verify they are not equal due to different DNS strings.
		#expect(error1 != error2)
	}

	/// Test that settingsGenerationFailed errors with the same reason are equal.
	@Test("SettingsGenerationFailed errors with same reason are equal")
	func testSettingsGenerationFailedEqualitySame() {
		// Create two errors with the same failure reason.
		let error1 = IntegrationError.settingsGenerationFailed("no peers")
		let error2 = IntegrationError.settingsGenerationFailed("no peers")

		// Verify they are equal.
		#expect(error1 == error2)
	}

	/// Test that settingsGenerationFailed errors with different reasons are not equal.
	@Test("SettingsGenerationFailed errors with different reasons are not equal")
	func testSettingsGenerationFailedEqualityDifferent() {
		// Create two errors with different failure reasons.
		let error1 = IntegrationError.settingsGenerationFailed("no peers")
		let error2 = IntegrationError.settingsGenerationFailed("no addresses")

		// Verify they are not equal due to different reasons.
		#expect(error1 != error2)
	}

	/// Test that packetFlowError errors with the same message are equal.
	@Test("PacketFlowError errors with same message are equal")
	func testPacketFlowErrorEqualitySame() {
		// Create two errors with the same error message.
		let error1 = IntegrationError.packetFlowError("timeout")
		let error2 = IntegrationError.packetFlowError("timeout")

		// Verify they are equal.
		#expect(error1 == error2)
	}

	/// Test that packetFlowError errors with different messages are not equal.
	@Test("PacketFlowError errors with different messages are not equal")
	func testPacketFlowErrorEqualityDifferent() {
		// Create two errors with different error messages.
		let error1 = IntegrationError.packetFlowError("timeout")
		let error2 = IntegrationError.packetFlowError("connection lost")

		// Verify they are not equal due to different messages.
		#expect(error1 != error2)
	}

	// MARK: - Different error type inequality

	/// Test that different error types are never equal.
	///
	/// Even if error types might seem related (like noIPv4Address and noIPv6Address),
	/// they represent different problems and should not be equal.
	@Test("Different error types are not equal")
	func testDifferentErrorTypesNotEqual() {
		// Create two different error types.
		// These are related (both address errors) but distinct error cases.
		let error1 = IntegrationError.noIPv4Address
		let error2 = IntegrationError.noIPv6Address

		// Verify they are not equal.
		// This ensures error handling code can distinguish between different error types.
		#expect(error1 != error2)
	}

	/// Test that noIPv4Address and invalidRoute errors are not equal.
	///
	/// This verifies that errors of completely different types (address vs route)
	/// are correctly identified as not equal.
	@Test("IPv4 address error and route error are not equal")
	func testAddressAndRouteNotEqual() {
		// Create errors of different types.
		let error1 = IntegrationError.noIPv4Address
		let error2 = IntegrationError.invalidRoute("10.0.0.0/8")

		// Verify they are not equal despite both being IntegrationError.
		#expect(error1 != error2)
	}
}
