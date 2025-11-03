// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import XCTest

@testable import WireGuard

/// Tests for BridgeError type and its LocalizedError conformance.
///
/// BridgeError represents FFI-specific failures when communicating with BoringTun.
/// These tests verify:
/// - Correct error descriptions for all error cases
/// - Sendable conformance for actor-based concurrency
/// - Equatable behavior for error comparison
final class BridgeErrorTests: XCTestCase {
	// MARK: - Error Description Tests

	/// Tests that tunnelCreationFailed provides informative error messages.
	///
	/// This error occurs when BoringTun's `new_tunnel()` returns null, typically
	/// due to invalid cryptographic keys. The error message should guide users
	/// toward verifying their key material.
	func testTunnelCreationFailedDescription() {
		let error = BridgeError.tunnelCreationFailed

		// Verify user-facing error message
		XCTAssertEqual(
			error.errorDescription,
			"Failed to create WireGuard tunnel"
		)

		// Verify technical reason
		XCTAssertEqual(
			error.failureReason,
			"BoringTun returned null when creating the tunnel."
		)

		// Verify recovery guidance
		XCTAssertEqual(
			error.recoverySuggestion,
			"Verify that the private key, peer public key, and optional pre-shared key "
				+ "are valid base64-encoded x25519 keys."
		)
	}

	/// Tests that invalidHandle provides informative error messages.
	///
	/// This error occurs when calling packet processing or statistics methods
	/// without first creating a tunnel. The error should guide users toward
	/// calling createTunnel() first.
	func testInvalidHandleDescription() {
		let error = BridgeError.invalidHandle

		// Verify user-facing error message
		XCTAssertEqual(
			error.errorDescription,
			"No active WireGuard tunnel"
		)

		// Verify technical reason
		XCTAssertEqual(
			error.failureReason,
			"Attempted to perform an operation without an active tunnel."
		)

		// Verify recovery guidance
		XCTAssertEqual(
			error.recoverySuggestion,
			"Create a tunnel using createTunnel() before calling packet processing or statistics methods."
		)
	}

	/// Tests operationFailed without a specific message.
	///
	/// When BoringTun returns an error result but doesn't provide details,
	/// we show a generic message with common failure causes.
	func testOperationFailedWithoutMessage() {
		let error = BridgeError.operationFailed(nil)

		// Verify user-facing error message
		XCTAssertEqual(
			error.errorDescription,
			"WireGuard operation failed"
		)

		// When no specific message is provided, show generic reason
		XCTAssertEqual(
			error.failureReason,
			"The operation completed but BoringTun returned an error result."
		)

		// Provide common troubleshooting steps
		XCTAssertEqual(
			error.recoverySuggestion,
			"This may indicate packet authentication failure, invalid tunnel state, or "
				+ "malformed input data. Check tunnel connectivity and peer configuration."
		)
	}

	/// Tests operationFailed with a specific error message.
	///
	/// When we have context about what failed, the failureReason should
	/// contain that specific message while keeping the generic description
	/// and recovery suggestion.
	func testOperationFailedWithMessage() {
		let message = "Packet authentication failed"
		let error = BridgeError.operationFailed(message)

		// Generic user-facing message
		XCTAssertEqual(
			error.errorDescription,
			"WireGuard operation failed"
		)

		// Specific failure reason when available
		XCTAssertEqual(
			error.failureReason,
			message
		)

		// Generic recovery suggestion still applies
		XCTAssertEqual(
			error.recoverySuggestion,
			"This may indicate packet authentication failure, invalid tunnel state, or "
				+ "malformed input data. Check tunnel connectivity and peer configuration."
		)
	}

	// MARK: - Sendable Conformance Tests

	/// Tests that BridgeError conforms to Sendable protocol.
	///
	/// BridgeError must be Sendable to cross actor boundaries, which is essential
	/// since BoringTunBridge is an actor. This test verifies the error can be
	/// captured and sent to async tasks without compiler warnings.
	func testSendableConformance() async {
		// Create an error in one isolation domain
		let error = BridgeError.tunnelCreationFailed

		// Send it to another isolation domain (async Task)
		await Task {
			// If this compiles without Sendable warnings, conformance is correct
			_ = error
		}.value
	}

	// MARK: - Equatable Tests

	/// Tests that BridgeError implements Equatable correctly.
	///
	/// Equatable conformance is important for:
	/// - Comparing errors in tests
	/// - Pattern matching in switch statements
	/// - Error deduplication in error handling logic
	///
	/// Associated values (like the optional String in operationFailed) must be
	/// compared correctly.
	func testEquality() {
		// Same error cases are equal
		XCTAssertEqual(
			BridgeError.tunnelCreationFailed,
			BridgeError.tunnelCreationFailed
		)

		XCTAssertEqual(
			BridgeError.invalidHandle,
			BridgeError.invalidHandle
		)

		// operationFailed with nil messages are equal
		XCTAssertEqual(
			BridgeError.operationFailed(nil),
			BridgeError.operationFailed(nil)
		)

		// operationFailed with identical messages are equal
		XCTAssertEqual(
			BridgeError.operationFailed("test"),
			BridgeError.operationFailed("test")
		)

		// Different error cases are not equal
		XCTAssertNotEqual(
			BridgeError.tunnelCreationFailed,
			BridgeError.invalidHandle
		)

		// operationFailed with different messages are not equal
		XCTAssertNotEqual(
			BridgeError.operationFailed("test1"),
			BridgeError.operationFailed("test2")
		)

		// operationFailed with nil vs non-nil message are not equal
		XCTAssertNotEqual(
			BridgeError.operationFailed(nil),
			BridgeError.operationFailed("test")
		)
	}
}
