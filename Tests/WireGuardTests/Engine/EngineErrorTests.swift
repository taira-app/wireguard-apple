// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for engine error types and localized error descriptions.
///
/// EngineError represents failures during tunnel engine operations. These tests
/// verify that error equality, descriptions, recovery suggestions, and failure
/// reasons work correctly. Proper error handling is critical for debugging and
/// providing actionable feedback to users.
struct EngineErrorTests {
	// MARK: - Error equality tests

	/// Verifies that two notConfigured errors are equal.
	///
	/// The notConfigured error has no associated data, so all instances should
	/// be considered equal. This is important for error handling logic that
	/// needs to distinguish between different error types.
	@Test("NotConfigured errors are equal")
	func notConfiguredErrorsAreEqual() {
		let error1 = EngineError.notConfigured
		let error2 = EngineError.notConfigured
		#expect(error1 == error2)
	}

	/// Verifies that two alreadyRunning errors are equal.
	///
	/// Like notConfigured, this error has no associated data, so all instances
	/// should compare as equal.
	@Test("AlreadyRunning errors are equal")
	func alreadyRunningErrorsAreEqual() {
		let error1 = EngineError.alreadyRunning
		let error2 = EngineError.alreadyRunning
		#expect(error1 == error2)
	}

	/// Verifies that two notRunning errors are equal.
	///
	/// This error has no associated data, so all instances should be equal.
	@Test("NotRunning errors are equal")
	func notRunningErrorsAreEqual() {
		let error1 = EngineError.notRunning
		let error2 = EngineError.notRunning
		#expect(error1 == error2)
	}

	/// Verifies that invalidPacket errors with identical data are equal.
	///
	/// The invalidPacket error includes the packet data as an associated value.
	/// Two errors with the same packet data should be considered equal.
	@Test("InvalidPacket errors with same data are equal")
	func invalidPacketErrorsWithSameDataAreEqual() {
		let packetData = Data([0x01, 0x02, 0x03, 0x04])
		let error1 = EngineError.invalidPacket(packetData)
		let error2 = EngineError.invalidPacket(packetData)
		#expect(error1 == error2)
	}

	/// Verifies that invalidPacket errors with different data are not equal.
	///
	/// Two errors with different packet data represent different error conditions
	/// and should not be considered equal.
	@Test("InvalidPacket errors with different data are not equal")
	func invalidPacketErrorsWithDifferentDataAreNotEqual() {
		let error1 = EngineError.invalidPacket(Data([0x01, 0x02]))
		let error2 = EngineError.invalidPacket(Data([0x03, 0x04]))
		#expect(error1 != error2)
	}

	/// Verifies that processingFailed errors with similar descriptions are equal.
	///
	/// Since Error doesn't conform to Equatable, we compare the string descriptions.
	/// Two processingFailed errors wrapping errors with the same description should
	/// be considered equal.
	@Test("ProcessingFailed errors with same underlying error are equal")
	func processingFailedErrorsWithSameUnderlyingErrorAreEqual() {
		struct TestError: Error, CustomStringConvertible {
			let description: String
		}

		let underlyingError = TestError(description: "Test failure")
		let error1 = EngineError.processingFailed(underlyingError)
		let error2 = EngineError.processingFailed(underlyingError)
		#expect(error1 == error2)
	}

	/// Verifies that endpointResolutionFailed errors with same hostname are equal.
	///
	/// The endpointResolutionFailed error includes the hostname that failed to
	/// resolve. Two errors with the same hostname should be equal.
	@Test("EndpointResolutionFailed errors with same hostname are equal")
	func endpointResolutionFailedErrorsWithSameHostnameAreEqual() {
		let error1 = EngineError.endpointResolutionFailed("vpn.example.com")
		let error2 = EngineError.endpointResolutionFailed("vpn.example.com")
		#expect(error1 == error2)
	}

	/// Verifies that endpointResolutionFailed errors with different hostnames are not equal.
	///
	/// Two errors with different hostnames represent different DNS failures and
	/// should not be considered equal.
	@Test("EndpointResolutionFailed errors with different hostnames are not equal")
	func endpointResolutionFailedErrorsWithDifferentHostnamesAreNotEqual() {
		let error1 = EngineError.endpointResolutionFailed("vpn1.example.com")
		let error2 = EngineError.endpointResolutionFailed("vpn2.example.com")
		#expect(error1 != error2)
	}

	/// Verifies that handshakeFailed errors with same reason are equal.
	///
	/// The handshakeFailed error includes a reason string. Two errors with the
	/// same reason should be considered equal.
	@Test("HandshakeFailed errors with same reason are equal")
	func handshakeFailedErrorsWithSameReasonAreEqual() {
		let error1 = EngineError.handshakeFailed("Timeout after 30s")
		let error2 = EngineError.handshakeFailed("Timeout after 30s")
		#expect(error1 == error2)
	}

	/// Verifies that handshakeFailed errors with different reasons are not equal.
	///
	/// Two errors with different reasons represent different handshake failures
	/// and should not be equal.
	@Test("HandshakeFailed errors with different reasons are not equal")
	func handshakeFailedErrorsWithDifferentReasonsAreNotEqual() {
		let error1 = EngineError.handshakeFailed("Timeout")
		let error2 = EngineError.handshakeFailed("Invalid response")
		#expect(error1 != error2)
	}

	/// Verifies that different error types are never equal.
	///
	/// This ensures that each error case is distinct and can be reliably
	/// distinguished in error handling code.
	@Test("Different error types are not equal")
	func differentErrorTypesAreNotEqual() {
		let notConfigured = EngineError.notConfigured
		let alreadyRunning = EngineError.alreadyRunning
		let notRunning = EngineError.notRunning
		let invalidPacket = EngineError.invalidPacket(Data([0x01]))
		let processingFailed = EngineError.processingFailed(NSError(domain: "test", code: 1))
		let endpointFailed = EngineError.endpointResolutionFailed("test.com")
		let handshakeFailed = EngineError.handshakeFailed("timeout")

		// Verify each error type is distinct from all others
		#expect(notConfigured != alreadyRunning)
		#expect(notConfigured != notRunning)
		#expect(notConfigured != invalidPacket)
		#expect(alreadyRunning != processingFailed)
		#expect(invalidPacket != endpointFailed)
		#expect(endpointFailed != handshakeFailed)
	}

	// MARK: - Error description tests

	/// Verifies that notConfigured error has the expected description.
	///
	/// The error description should clearly explain that the tunnel lacks
	/// configuration and cannot start.
	@Test("NotConfigured error has correct description")
	func notConfiguredErrorHasCorrectDescription() {
		let error = EngineError.notConfigured
		#expect(error.errorDescription == "The tunnel is not configured.")
	}

	/// Verifies that alreadyRunning error has the expected description.
	///
	/// The description should indicate that the tunnel is already active and
	/// cannot be started again.
	@Test("AlreadyRunning error has correct description")
	func alreadyRunningErrorHasCorrectDescription() {
		let error = EngineError.alreadyRunning
		#expect(error.errorDescription == "The tunnel is already running.")
	}

	/// Verifies that notRunning error has the expected description.
	///
	/// The description should explain that the tunnel is not active and the
	/// requested operation cannot be performed.
	@Test("NotRunning error has correct description")
	func notRunningErrorHasCorrectDescription() {
		let error = EngineError.notRunning
		#expect(error.errorDescription == "The tunnel is not running.")
	}

	/// Verifies that invalidPacket error has the expected description.
	///
	/// The description should indicate that a packet was malformed and cannot
	/// be processed.
	@Test("InvalidPacket error has correct description")
	func invalidPacketErrorHasCorrectDescription() {
		let error = EngineError.invalidPacket(Data([0x01, 0x02]))
		#expect(error.errorDescription == "Received an invalid packet that cannot be processed.")
	}

	/// Verifies that processingFailed error includes the underlying error.
	///
	/// The description should explain that packet processing failed and include
	/// the localized description of the underlying error for context.
	@Test("ProcessingFailed error has correct description")
	func processingFailedErrorHasCorrectDescription() {
		let underlyingError = NSError(
			domain: "TestDomain",
			code: 42,
			userInfo: [NSLocalizedDescriptionKey: "Underlying failure"]
		)
		let error = EngineError.processingFailed(underlyingError)
		#expect(error.errorDescription?.contains("Packet processing failed") == true)
		#expect(error.errorDescription?.contains("Underlying failure") == true)
	}

	/// Verifies that endpointResolutionFailed error includes the hostname.
	///
	/// The description should explain that DNS resolution failed and include
	/// the specific hostname that could not be resolved.
	@Test("EndpointResolutionFailed error has correct description")
	func endpointResolutionFailedErrorHasCorrectDescription() {
		let error = EngineError.endpointResolutionFailed("vpn.example.com")
		#expect(error.errorDescription == "Could not resolve endpoint hostname 'vpn.example.com'.")
	}

	/// Verifies that handshakeFailed error includes the failure reason.
	///
	/// The description should explain that the WireGuard handshake failed and
	/// include the specific reason for the failure.
	@Test("HandshakeFailed error has correct description")
	func handshakeFailedErrorHasCorrectDescription() {
		let error = EngineError.handshakeFailed("Connection timeout")
		#expect(error.errorDescription == "WireGuard handshake failed: Connection timeout")
	}

	// MARK: - Recovery suggestion tests

	/// Verifies that notConfigured error provides actionable recovery guidance.
	///
	/// The recovery suggestion should guide users to provide a valid configuration
	/// before attempting to start the tunnel.
	@Test("NotConfigured error has helpful recovery suggestion")
	func notConfiguredErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.notConfigured
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("configuration") == true)
		#expect(suggestion?.contains("peer") == true)
	}

	/// Verifies that alreadyRunning error provides actionable recovery guidance.
	///
	/// The recovery suggestion should advise stopping the tunnel before restarting
	/// or checking if it's already in the desired state.
	@Test("AlreadyRunning error has helpful recovery suggestion")
	func alreadyRunningErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.alreadyRunning
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("Stop") == true)
	}

	/// Verifies that notRunning error provides actionable recovery guidance.
	///
	/// The recovery suggestion should advise starting the tunnel before attempting
	/// operations that require an active connection.
	@Test("NotRunning error has helpful recovery suggestion")
	func notRunningErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.notRunning
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("Start") == true)
	}

	/// Verifies that invalidPacket error provides actionable recovery guidance.
	///
	/// The recovery suggestion should warn about potential network issues or
	/// attacks and guide users to check network conditions.
	@Test("InvalidPacket error has helpful recovery suggestion")
	func invalidPacketErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.invalidPacket(Data([0x01]))
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("network") == true)
	}

	/// Verifies that endpointResolutionFailed error provides actionable recovery guidance.
	///
	/// The recovery suggestion should advise checking network connectivity, DNS
	/// settings, and hostname correctness.
	@Test("EndpointResolutionFailed error has helpful recovery suggestion")
	func endpointResolutionFailedErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.endpointResolutionFailed("test.com")
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("DNS") == true)
		#expect(suggestion?.contains("network") == true)
	}

	/// Verifies that handshakeFailed error provides actionable recovery guidance.
	///
	/// The recovery suggestion should advise verifying keys, checking connectivity,
	/// and ensuring the peer is reachable.
	@Test("HandshakeFailed error has helpful recovery suggestion")
	func handshakeFailedErrorHasHelpfulRecoverySuggestion() {
		let error = EngineError.handshakeFailed("timeout")
		let suggestion = error.recoverySuggestion
		#expect(suggestion?.contains("public key") == true)
		#expect(suggestion?.contains("connectivity") == true)
	}

	// MARK: - Failure reason tests

	/// Verifies that notConfigured error provides technical failure details.
	///
	/// The failure reason should explain the technical cause: no configuration
	/// was provided or it was cleared before starting.
	@Test("NotConfigured error has detailed failure reason")
	func notConfiguredErrorHasDetailedFailureReason() {
		let error = EngineError.notConfigured
		let reason = error.failureReason
		#expect(reason?.contains("configuration") == true)
	}

	/// Verifies that invalidPacket error includes packet size in failure reason.
	///
	/// The failure reason should provide technical details including the size
	/// of the malformed packet, which is useful for debugging.
	@Test("InvalidPacket error failure reason includes packet size")
	func invalidPacketErrorFailureReasonIncludesPacketSize() {
		let packetData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
		let error = EngineError.invalidPacket(packetData)
		let reason = error.failureReason
		#expect(reason?.contains("5 bytes") == true)
	}

	/// Verifies that processingFailed error includes underlying error details.
	///
	/// The failure reason should include information about the underlying error
	/// that caused the processing to fail, which is essential for debugging.
	@Test("ProcessingFailed error failure reason includes underlying error")
	func processingFailedErrorFailureReasonIncludesUnderlyingError() {
		let underlyingError = NSError(
			domain: "TestDomain",
			code: 123,
			userInfo: [:]
		)
		let error = EngineError.processingFailed(underlyingError)
		let reason = error.failureReason
		#expect(reason?.contains("BoringTun") == true)
		#expect(reason?.contains("123") == true)
	}

	/// Verifies that endpointResolutionFailed error includes technical DNS details.
	///
	/// The failure reason should explain potential causes like DNS server issues,
	/// non-existent hostname, or network unavailability.
	@Test("EndpointResolutionFailed error failure reason includes DNS details")
	func endpointResolutionFailedErrorFailureReasonIncludesDNSDetails() {
		let error = EngineError.endpointResolutionFailed("vpn.example.com")
		let reason = error.failureReason
		#expect(reason?.contains("DNS") == true)
		#expect(reason?.contains("vpn.example.com") == true)
	}

	/// Verifies that handshakeFailed error includes the specific failure reason.
	///
	/// The failure reason should provide technical details about why the handshake
	/// did not complete, which is critical for troubleshooting connection issues.
	@Test("HandshakeFailed error failure reason includes specific details")
	func handshakeFailedErrorFailureReasonIncludesSpecificDetails() {
		let error = EngineError.handshakeFailed("Invalid response from peer")
		let reason = error.failureReason
		#expect(reason?.contains("Invalid response from peer") == true)
	}

	// MARK: - Sendable conformance tests

	/// Verifies that EngineError can be safely sent across concurrency boundaries.
	///
	/// EngineError conforms to Sendable, which means it can be safely shared
	/// between actors and async tasks. This test verifies that we can capture
	/// an EngineError in an async context, which is essential for async error
	/// handling across actor boundaries.
	@Test("EngineError can be sent across concurrency domains")
	func engineErrorCanBeSentAcrossConcurrencyDomains() async {
		let error = EngineError.notConfigured

		// This compiles because EngineError is Sendable. We create an async task
		// that captures the error value, demonstrating that errors can cross
		// concurrency boundaries safely for async error propagation.
		await withCheckedContinuation { continuation in
			Task {
				// Capture error in async context to verify Sendable conformance
				_ = error
				continuation.resume()
			}
		}
	}
}
