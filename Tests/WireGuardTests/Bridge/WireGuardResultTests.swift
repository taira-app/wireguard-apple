// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTunFFI
import XCTest

@testable import WireGuard

/// Tests for WireGuardResult and ResultOperation types.
///
/// WireGuardResult represents the outcome of BoringTun packet processing operations.
/// These tests verify:
/// - Correct conversion from BoringTun's C FFI result structure
/// - All ResultOperation enum cases match BoringTun's values
/// - Sendable and Equatable conformance
/// - Edge case handling (unknown operation codes)
final class WireGuardResultTests: XCTestCase {
	// MARK: - ResultOperation Raw Value Tests

	/// Tests that ResultOperation enum raw values match BoringTun's C enum.
	///
	/// These raw values MUST match exactly with BoringTun's result_type enum
	/// defined in wireguard_ffi.h. Any mismatch would cause incorrect operation
	/// interpretation and break packet processing.
	///
	/// From wireguard_ffi.h:
	/// - WRITE_TO_NETWORK = 1
	/// - WIREGUARD_DONE = 0
	/// - WIREGUARD_ERROR = 2
	/// - WRITE_TO_TUNNEL_IPV4 = 4
	/// - WRITE_TO_TUNNEL_IPV6 = 6
	func testResultOperationRawValues() {
		// Verify each enum case has the correct raw value from BoringTun
		XCTAssertEqual(ResultOperation.done.rawValue, 0)
		XCTAssertEqual(ResultOperation.writeToNetwork.rawValue, 1)
		XCTAssertEqual(ResultOperation.error.rawValue, 2)
		XCTAssertEqual(ResultOperation.writeToTunnelIPv4.rawValue, 4)
		XCTAssertEqual(ResultOperation.writeToTunnelIPv6.rawValue, 6)
	}

	/// Tests that ResultOperation can be initialized from raw values.
	///
	/// This is critical for the WireGuardResult initializer which converts
	/// BoringTun's C enum values to Swift enum cases. Unknown values should
	/// return nil and be handled as errors.
	func testResultOperationFromRawValue() {
		// Valid raw values create correct enum cases
		XCTAssertEqual(ResultOperation(rawValue: 0), .done)
		XCTAssertEqual(ResultOperation(rawValue: 1), .writeToNetwork)
		XCTAssertEqual(ResultOperation(rawValue: 2), .error)
		XCTAssertEqual(ResultOperation(rawValue: 4), .writeToTunnelIPv4)
		XCTAssertEqual(ResultOperation(rawValue: 6), .writeToTunnelIPv6)

		// Invalid raw values return nil
		XCTAssertNil(ResultOperation(rawValue: 3))
		XCTAssertNil(ResultOperation(rawValue: 5))
		XCTAssertNil(ResultOperation(rawValue: 99))
	}

	// MARK: - WireGuardResult Initialization Tests

	/// Tests creating WireGuardResult from BoringTun's C result structure.
	///
	/// The initializer must correctly convert the C wireguard_result struct
	/// into Swift types. This is the primary way results are created from
	/// FFI function calls.
	func testInitFromCResult() {
		// Test with writeToNetwork operation and size
		var cResult = wireguard_result()
		cResult.op = result_type(rawValue: 1)  // WRITE_TO_NETWORK
		cResult.size = 148  // Typical handshake message size

		let result = WireGuardResult(cResult: cResult)

		XCTAssertEqual(result.operation, .writeToNetwork)
		XCTAssertEqual(result.size, 148)
	}

	/// Tests that unknown C operation codes are converted to .error.
	///
	/// If BoringTun returns an unknown operation code (which shouldn't happen
	/// but might in future versions), we treat it as an error rather than
	/// crashing. The ?? .error fallback in the initializer handles this.
	func testInitFromCResultWithUnknownOperation() {
		// Simulate an unknown operation code from BoringTun
		var cResult = wireguard_result()
		cResult.op = result_type(rawValue: 99)  // Invalid code
		cResult.size = 0

		let result = WireGuardResult(cResult: cResult)

		// Unknown operations should default to .error
		XCTAssertEqual(result.operation, .error)
		XCTAssertEqual(result.size, 0)
	}

	/// Tests all valid operation types with various sizes.
	///
	/// Verifies that each ResultOperation case can be correctly created
	/// from its corresponding C enum value and that size values are preserved.
	func testAllOperationTypes() {
		let testCases: [(UInt32, ResultOperation, Int)] = [
			(0, .done, 0),                      // No output
			(1, .writeToNetwork, 148),          // Handshake message
			(2, .error, 0),                     // Error, no output
			(4, .writeToTunnelIPv4, 1500),      // IPv4 packet
			(6, .writeToTunnelIPv6, 1500),      // IPv6 packet
		]

		for (rawValue, expectedOp, expectedSize) in testCases {
			var cResult = wireguard_result()
			cResult.op = result_type(rawValue: rawValue)
			cResult.size = expectedSize

			let result = WireGuardResult(cResult: cResult)

			XCTAssertEqual(result.operation, expectedOp, "Failed for raw value \(rawValue)")
			XCTAssertEqual(result.size, expectedSize, "Failed for raw value \(rawValue)")
		}
	}

	// MARK: - Sendable Conformance Tests

	/// Tests that WireGuardResult conforms to Sendable protocol.
	///
	/// WireGuardResult must be Sendable because it's returned from actor methods
	/// in BoringTunBridge. This test verifies it can cross actor boundaries.
	func testSendableConformance() async {
		// Create a result in one isolation domain
		var cResult = wireguard_result()
		cResult.op = result_type(rawValue: 1)
		cResult.size = 100
		let result = WireGuardResult(cResult: cResult)

		// Send it to another isolation domain
		await Task {
			// If this compiles without Sendable warnings, conformance is correct
			let _ = result
		}.value
	}

	// MARK: - Equatable Tests

	/// Tests that WireGuardResult implements Equatable correctly.
	///
	/// Equatable is important for testing and for comparing results in
	/// application logic. Two results are equal if both their operation
	/// and size match.
	func testEquality() {
		// Create two identical results
		var cResult1 = wireguard_result()
		cResult1.op = result_type(rawValue: 1)  // writeToNetwork
		cResult1.size = 148

		var cResult2 = wireguard_result()
		cResult2.op = result_type(rawValue: 1)  // writeToNetwork
		cResult2.size = 148

		let result1 = WireGuardResult(cResult: cResult1)
		let result2 = WireGuardResult(cResult: cResult2)

		// Same operation and size are equal
		XCTAssertEqual(result1, result2)

		// Different operations are not equal
		var cResult3 = wireguard_result()
		cResult3.op = result_type(rawValue: 0)  // done
		cResult3.size = 148
		let result3 = WireGuardResult(cResult: cResult3)

		XCTAssertNotEqual(result1, result3)

		// Different sizes are not equal
		var cResult4 = wireguard_result()
		cResult4.op = result_type(rawValue: 1)  // writeToNetwork
		cResult4.size = 200
		let result4 = WireGuardResult(cResult: cResult4)

		XCTAssertNotEqual(result1, result4)
	}
}
