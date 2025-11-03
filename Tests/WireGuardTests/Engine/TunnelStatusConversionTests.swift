// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation
import Testing

@testable import WireGuard

/// Tests for tunnel status time and quality conversions.
///
/// These tests verify that TunnelStatus correctly converts bridge statistics
/// into Swift-friendly types and provides accurate quality assessments based
/// on packet loss and handshake timing.
struct TunnelStatusConversionTests {
	// MARK: - Handshake time conversion tests

	/// Verifies that lastHandshakeTime returns nil when no handshake has occurred.
	///
	/// The bridge layer uses -1 to indicate no handshake. TunnelStatus should
	/// convert this to nil for a more idiomatic Swift API.
	@Test("Last handshake time is nil when no handshake")
	func lastHandshakeTimeIsNilWhenNoHandshake() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: -1,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.lastHandshakeTime == nil)
		#expect(status.hasHandshake == false)
	}

	/// Verifies that lastHandshakeTime correctly calculates the timestamp.
	///
	/// When the bridge reports 30 seconds since last handshake, the timestamp
	/// should be approximately 30 seconds in the past from now.
	@Test("Last handshake time calculated correctly")
	func lastHandshakeTimeCalculatedCorrectly() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 30,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		// Get the handshake time and verify it's approximately 30 seconds ago
		guard let handshakeTime = status.lastHandshakeTime else {
			Issue.record("Handshake time should not be nil")
			return
		}

		let timeSince = Date().timeIntervalSince(handshakeTime)

		// Allow 1 second tolerance for test execution time
		#expect(timeSince >= 29 && timeSince <= 31)
		#expect(status.hasHandshake == true)
	}

	/// Verifies that a zero time since handshake means just now.
	///
	/// When the bridge reports 0 seconds since handshake, the timestamp should
	/// be very recent (within the last second).
	@Test("Zero time since handshake means just now")
	func zeroTimeSinceHandshakeMeansJustNow() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		guard let handshakeTime = status.lastHandshakeTime else {
			Issue.record("Handshake time should not be nil")
			return
		}

		let timeSince = Date().timeIntervalSince(handshakeTime)

		// Should be very recent (within 1 second)
		#expect(timeSince >= 0 && timeSince <= 1)
	}

	// MARK: - Round-trip time conversion tests

	/// Verifies that estimatedRoundTripTime returns nil when not measured.
	///
	/// The bridge layer uses -1 to indicate round-trip time has not been measured.
	/// TunnelStatus should convert this to nil for a more idiomatic Swift API.
	@Test("Estimated round-trip time is nil when not measured")
	func estimatedRoundTripTimeIsNilWhenNotMeasured() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.estimatedRTT == nil)
		#expect(status.hasRTT == false)
	}

	/// Verifies that estimated round-trip time is correctly converted from milliseconds to seconds.
	///
	/// The bridge layer reports round-trip time in milliseconds as Int32. TunnelStatus
	/// should convert this to seconds as TimeInterval (Double).
	@Test("Estimated round-trip time converted from milliseconds to seconds")
	func estimatedRoundTripTimeConvertedFromMillisecondsToSeconds() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: 150  // 150 milliseconds
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		guard let roundTripTime = status.estimatedRTT else {
			Issue.record("Round-trip time should not be nil")
			return
		}

		// 150 ms = 0.15 seconds
		#expect(abs(roundTripTime - 0.15) < 0.001)
		#expect(status.hasRTT == true)
	}

	/// Verifies that zero round-trip time is handled correctly.
	///
	/// A reported round-trip time of 0 milliseconds should convert to 0 seconds, not nil.
	@Test("Zero round-trip time is handled correctly")
	func zeroRoundTripTimeIsHandledCorrectly() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: 0
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.estimatedRTT == 0.0)
		#expect(status.hasRTT == true)
	}

	// MARK: - Handshake staleness tests

	/// Verifies that a recent handshake is not considered stale.
	///
	/// Handshakes less than 180 seconds old should not be stale.
	@Test("Recent handshake is not stale")
	func recentHandshakeIsNotStale() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 120,  // 2 minutes
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.isHandshakeStale == false)
	}

	/// Verifies that a handshake older than 180 seconds is considered stale.
	///
	/// WireGuard considers handshakes stale after 180 seconds, so TunnelStatus
	/// should reflect this.
	@Test("Old handshake is stale")
	func oldHandshakeIsStale() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 200,  // Over 3 minutes
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.isHandshakeStale == true)
	}

	/// Verifies that no handshake is not considered stale.
	///
	/// If no handshake has occurred, isHandshakeStale should return false
	/// rather than true, since there's nothing to be stale.
	@Test("No handshake is not considered stale")
	func noHandshakeIsNotConsideredStale() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: -1,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.isHandshakeStale == false)
	}

	// MARK: - Quality description tests

	/// Verifies that excellent quality is reported for minimal loss.
	///
	/// Loss below 1% should be reported as "Excellent".
	@Test("Excellent quality for minimal loss")
	func excellentQualityForMinimalLoss() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.005,  // 0.5%
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.qualityDescription == "Excellent")
	}

	/// Verifies that good quality is reported for low loss.
	///
	/// Loss between 1% and 5% should be reported as "Good".
	@Test("Good quality for low loss")
	func goodQualityForLowLoss() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.03,  // 3%
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.qualityDescription == "Good")
	}

	/// Verifies that fair quality is reported for moderate loss.
	///
	/// Loss between 5% and 10% should be reported as "Fair".
	@Test("Fair quality for moderate loss")
	func fairQualityForModerateLoss() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.07,  // 7%
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.qualityDescription == "Fair")
	}

	/// Verifies that poor quality is reported for high loss.
	///
	/// Loss above 10% should be reported as "Poor".
	@Test("Poor quality for high loss")
	func poorQualityForHighLoss() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.15,  // 15%
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.qualityDescription == "Poor")
	}

	// MARK: - Helper methods

	/// Creates a stats structure with the given values.
	///
	/// This helper constructs a BoringTun stats structure for testing. All
	/// parameters default to safe values if not specified.
	///
	/// - Parameters:
	///   - timeSinceLastHandshake: Seconds since last handshake (-1 for none)
	///   - transmittedBytes: Transmitted bytes
	///   - receivedBytes: Received bytes
	///   - estimatedLoss: Packet loss fraction (0.0-1.0)
	///   - estimatedRoundTripTime: Round-trip time in milliseconds (-1 for unmeasured)
	/// - Returns: A stats structure
	private func createStats(
		timeSinceLastHandshake: Int64 = 0,
		transmittedBytes: Int = 0,
		receivedBytes: Int = 0,
		estimatedLoss: Float = 0,
		estimatedRoundTripTime: Int32 = -1
	) -> stats {
		stats(
			time_since_last_handshake: timeSinceLastHandshake,
			tx_bytes: transmittedBytes,
			rx_bytes: receivedBytes,
			estimated_loss: estimatedLoss,
			estimated_rtt: estimatedRoundTripTime,
			reserved: (
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
			)
		)
	}
}
