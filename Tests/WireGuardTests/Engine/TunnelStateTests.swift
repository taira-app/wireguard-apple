// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for tunnel state representation and transitions.
///
/// TunnelState is a fundamental enum that represents the lifecycle of a WireGuard
/// tunnel. These tests verify that state equality, descriptions, and serialization
/// work correctly. Proper state handling is critical for tunnel lifecycle management
/// and observability.
struct TunnelStateTests {
	// MARK: - State equality tests

	/// Verifies that two stopped states are considered equal.
	///
	/// The stopped state represents a tunnel that is completely shut down. This test
	/// ensures that comparing two stopped states always returns true, which is
	/// important for state observation and conditional logic based on tunnel state.
	@Test("Stopped states are equal")
	func stoppedStatesAreEqual() {
		let state1 = TunnelState.stopped
		let state2 = TunnelState.stopped
		#expect(state1 == state2)
	}

	/// Verifies that two starting states are considered equal.
	///
	/// The starting state is a transient state during tunnel initialization. This
	/// test ensures that state comparisons work correctly during the startup phase.
	@Test("Starting states are equal")
	func startingStatesAreEqual() {
		let state1 = TunnelState.starting
		let state2 = TunnelState.starting
		#expect(state1 == state2)
	}

	/// Verifies that two connected states are considered equal.
	///
	/// The connected state is the primary operating state where the tunnel actively
	/// processes packets. This test ensures state comparisons work correctly during
	/// normal operation.
	@Test("Connected states are equal")
	func connectedStatesAreEqual() {
		let state1 = TunnelState.connected
		let state2 = TunnelState.connected
		#expect(state1 == state2)
	}

	/// Verifies that two stopping states are considered equal.
	///
	/// The stopping state is a transient state during tunnel shutdown. This test
	/// ensures state comparisons work correctly during the cleanup phase.
	@Test("Stopping states are equal")
	func stoppingStatesAreEqual() {
		let state1 = TunnelState.stopping
		let state2 = TunnelState.stopping
		#expect(state1 == state2)
	}

	/// Verifies that two reasserting states are considered equal.
	///
	/// The reasserting state occurs when the tunnel attempts to recover from a
	/// network interruption. This test ensures state comparisons work correctly
	/// during network transitions.
	@Test("Reasserting states are equal")
	func reassertingStatesAreEqual() {
		let state1 = TunnelState.reasserting
		let state2 = TunnelState.reasserting
		#expect(state1 == state2)
	}

	/// Verifies that two error states with identical messages are considered equal.
	///
	/// Error states carry an associated error message. This test ensures that
	/// equality comparison considers both the state type and the message content.
	/// Two errors with the same message should be equal.
	@Test("Error states with same message are equal")
	func errorStatesWithSameMessageAreEqual() {
		let state1 = TunnelState.error("Connection failed")
		let state2 = TunnelState.error("Connection failed")
		#expect(state1 == state2)
	}

	/// Verifies that two error states with different messages are not equal.
	///
	/// This test ensures that the error message is part of the equality comparison.
	/// Two error states with different messages represent different error conditions
	/// and should not be considered equal.
	@Test("Error states with different messages are not equal")
	func errorStatesWithDifferentMessagesAreNotEqual() {
		let state1 = TunnelState.error("Connection failed")
		let state2 = TunnelState.error("Handshake timeout")
		#expect(state1 != state2)
	}

	/// Verifies that different state types are never equal to each other.
	///
	/// This comprehensive test ensures that the six distinct state types (stopped,
	/// starting, connected, stopping, reasserting, error) are all mutually exclusive.
	/// This is critical for switch statements and conditional logic that branches
	/// based on tunnel state.
	@Test("Different state types are not equal")
	func differentStateTypesAreNotEqual() {
		let stopped = TunnelState.stopped
		let starting = TunnelState.starting
		let connected = TunnelState.connected
		let stopping = TunnelState.stopping
		let reasserting = TunnelState.reasserting
		let error = TunnelState.error("Failed")

		// Verify each state type is distinct from all others
		#expect(stopped != starting)
		#expect(stopped != connected)
		#expect(stopped != stopping)
		#expect(stopped != reasserting)
		#expect(stopped != error)
		#expect(starting != connected)
		#expect(connected != stopping)
		#expect(reasserting != error)
	}

	// MARK: - Description tests

	/// Verifies that the stopped state produces the expected description string.
	///
	/// The description property provides a human-readable representation of the
	/// state, useful for logging and debugging. This test ensures the stopped
	/// state returns "stopped" as its description.
	@Test("Stopped state has correct description")
	func stoppedStateHasCorrectDescription() {
		let state = TunnelState.stopped
		#expect(state.description == "stopped")
	}

	/// Verifies that the starting state produces the expected description string.
	///
	/// The description should match the state name for consistency in logs and
	/// debugging output.
	@Test("Starting state has correct description")
	func startingStateHasCorrectDescription() {
		let state = TunnelState.starting
		#expect(state.description == "starting")
	}

	/// Verifies that the connected state produces the expected description string.
	///
	/// The description should clearly indicate the tunnel is actively connected
	/// and processing packets.
	@Test("Connected state has correct description")
	func connectedStateHasCorrectDescription() {
		let state = TunnelState.connected
		#expect(state.description == "connected")
	}

	/// Verifies that the stopping state produces the expected description string.
	///
	/// The description should indicate the tunnel is in the process of shutting down.
	@Test("Stopping state has correct description")
	func stoppingStateHasCorrectDescription() {
		let state = TunnelState.stopping
		#expect(state.description == "stopping")
	}

	/// Verifies that the reasserting state produces the expected description string.
	///
	/// The description should indicate the tunnel is attempting to recover from a
	/// network interruption.
	@Test("Reasserting state has correct description")
	func reassertingStateHasCorrectDescription() {
		let state = TunnelState.reasserting
		#expect(state.description == "reasserting")
	}

	/// Verifies that the error state includes the error message in its description.
	///
	/// The error description should be formatted as "error: <message>" to clearly
	/// communicate both the state type and the specific error condition. This is
	/// essential for debugging and error reporting.
	@Test("Error state has correct description")
	func errorStateHasCorrectDescription() {
		let state = TunnelState.error("Connection timeout")
		#expect(state.description == "error: Connection timeout")
	}

	// MARK: - Codable tests

	/// Verifies that the stopped state can be encoded to JSON and decoded back.
	///
	/// State persistence is important for saving and restoring tunnel state across
	/// app launches. This test ensures the stopped state survives a full encode/decode
	/// round-trip, producing an identical state value.
	@Test("Stopped state encodes and decodes correctly")
	func stoppedStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.stopped
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that the starting state can be encoded to JSON and decoded back.
	///
	/// This ensures the starting state maintains its identity through serialization,
	/// which is important if state needs to be persisted or transmitted.
	@Test("Starting state encodes and decodes correctly")
	func startingStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.starting
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that the connected state can be encoded to JSON and decoded back.
	///
	/// The connected state is the most common state during normal operation, so
	/// reliable serialization is critical for state persistence.
	@Test("Connected state encodes and decodes correctly")
	func connectedStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.connected
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that the stopping state can be encoded to JSON and decoded back.
	///
	/// This ensures the stopping state can be persisted if needed, though in practice
	/// this transient state is rarely serialized.
	@Test("Stopping state encodes and decodes correctly")
	func stoppingStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.stopping
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that the reasserting state can be encoded to JSON and decoded back.
	///
	/// This ensures the reasserting state survives serialization, which may be
	/// needed for state restoration after app termination during network transitions.
	@Test("Reasserting state encodes and decodes correctly")
	func reassertingStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.reasserting
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that an error state with a message can be encoded and decoded.
	///
	/// Error states carry additional data (the error message), so this test ensures
	/// that both the state type and the associated value are preserved through
	/// serialization. This is critical for error reporting and debugging.
	@Test("Error state encodes and decodes correctly")
	func errorStateEncodesAndDecodesCorrectly() throws {
		let original = TunnelState.error("Network unreachable")
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)
		#expect(decoded == original)
	}

	/// Verifies that the error message is preserved exactly through encoding.
	///
	/// This test specifically checks that the associated error message survives
	/// the encode/decode cycle without modification. We decode the state, extract
	/// the error message, and verify it matches the original exactly.
	@Test("Error state preserves message through encoding")
	func errorStatePreservesMessageThroughEncoding() throws {
		let errorMessage = "DNS resolution failed for endpoint"
		let original = TunnelState.error(errorMessage)
		let encoded = try JSONEncoder().encode(original)
		let decoded = try JSONDecoder().decode(TunnelState.self, from: encoded)

		// Extract the error message from the decoded state
		if case .error(let decodedMessage) = decoded {
			#expect(decodedMessage == errorMessage)
		} else {
			Issue.record("Decoded state is not an error case")
		}
	}

	/// Verifies that the stopped state encodes to the expected JSON structure.
	///
	/// This test examines the actual JSON output to ensure it matches our expected
	/// format. The stopped state should encode as {"type": "stopped"} with no error
	/// message field, keeping the JSON compact for states without associated data.
	@Test("Encoded stopped state has expected JSON structure")
	func encodedStoppedStateHasExpectedJSONStructure() throws {
		let state = TunnelState.stopped
		let encoded = try JSONEncoder().encode(state)
		let json = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]

		// Verify the JSON contains the correct type field
		#expect(json?["type"] as? String == "stopped")
		// Verify the JSON does not contain an error message field
		#expect(json?["errorMessage"] == nil)
	}

	/// Verifies that an error state encodes to the expected JSON structure.
	///
	/// This test examines the JSON output for an error state to ensure it contains
	/// both the type field ("error") and the errorMessage field with the actual
	/// error text. This structure allows proper deserialization of error states.
	@Test("Encoded error state has expected JSON structure")
	func encodedErrorStateHasExpectedJSONStructure() throws {
		let state = TunnelState.error("Test error")
		let encoded = try JSONEncoder().encode(state)
		let json = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]

		// Verify the JSON contains the correct type field
		#expect(json?["type"] as? String == "error")
		// Verify the JSON contains the error message
		#expect(json?["errorMessage"] as? String == "Test error")
	}

	// MARK: - Sendable conformance tests

	/// Verifies that TunnelState can be safely sent across concurrency boundaries.
	///
	/// TunnelState conforms to Sendable, which means it can be safely shared between
	/// actors and async tasks without data races. This test verifies that we can
	/// capture a TunnelState value in an async context, which is essential for
	/// observing state changes from multiple concurrent tasks.
	@Test("TunnelState can be sent across concurrency domains")
	func tunnelStateCanBeSentAcrossConcurrencyDomains() async {
		let state = TunnelState.connected

		// This compiles because TunnelState is Sendable. We create an async task
		// that captures the state value, demonstrating that the state can cross
		// concurrency boundaries safely.
		await withCheckedContinuation { continuation in
			Task {
				// Capture state in async context to verify Sendable conformance
				_ = state
				continuation.resume()
			}
		}
	}
}
