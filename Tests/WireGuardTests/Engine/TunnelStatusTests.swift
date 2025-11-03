// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation
import Testing

@testable import WireGuard

/// Tests for tunnel status basic properties and equality.
///
/// TunnelStatus wraps the low-level TunnelStatistics and provides a more
/// ergonomic Swift API. These tests verify initialization, basic property access,
/// and equality comparison.
struct TunnelStatusTests {
	// MARK: - Initialization tests

	/// Verifies that TunnelStatus correctly wraps bridge statistics.
	///
	/// The TunnelStatus initializer should store the bridge statistics and make
	/// them accessible through the internal bridgeStatistics property.
	@Test("TunnelStatus wraps bridge statistics")
	func tunnelStatusWrapsBridgeStatistics() {
		// Create bridge statistics with known values
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 30,
				transmittedBytes: 1024,
				receivedBytes: 2048,
				estimatedLoss: 0.05,
				estimatedRoundTripTime: 50
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		// Verify the bridge statistics are accessible
		#expect(status.bridgeStatistics == bridgeStats)
	}

	// MARK: - Byte conversion tests

	/// Verifies that transmitted bytes are correctly converted from UInt to UInt64.
	///
	/// The bridge layer uses UInt for byte counts, which may be 32-bit or 64-bit
	/// depending on platform. TunnelStatus should normalize this to UInt64 for
	/// consistency across all platforms.
	@Test("Transmitted bytes converted to UInt64")
	func transmittedBytesConvertedToUInt64() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 12_345_678,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.transmittedBytes == 12_345_678)
	}

	/// Verifies that received bytes are correctly converted from UInt to UInt64.
	///
	/// Similar to transmitted bytes, received bytes should be normalized to UInt64
	/// for cross-platform consistency.
	@Test("Received bytes converted to UInt64")
	func receivedBytesConvertedToUInt64() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 87_654_321,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.receivedBytes == 87_654_321)
	}

	// MARK: - Loss preservation tests

	/// Verifies that estimated loss is passed through unchanged.
	///
	/// The loss value is already a Float between 0.0 and 1.0, so it should be
	/// accessible directly without conversion.
	@Test("Estimated loss passed through unchanged")
	func estimatedLossPassedThroughUnchanged() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.025,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(abs(status.estimatedLoss - 0.025) < 0.001)
	}

	// MARK: - Equality tests

	/// Verifies that two status instances with identical statistics are equal.
	///
	/// Equality should be based on the underlying bridge statistics.
	@Test("Status instances with same statistics are equal")
	func statusInstancesWithSameStatisticsAreEqual() {
		let cStats = createStats(
			timeSinceLastHandshake: 30,
			transmittedBytes: 1024,
			receivedBytes: 2048,
			estimatedLoss: 0.05,
			estimatedRoundTripTime: 50
		)

		let bridgeStats1 = TunnelStatistics(cStats: cStats)
		let bridgeStats2 = TunnelStatistics(cStats: cStats)

		let status1 = TunnelStatus(bridgeStatistics: bridgeStats1)
		let status2 = TunnelStatus(bridgeStatistics: bridgeStats2)

		#expect(status1 == status2)
	}

	/// Verifies that status instances with different statistics are not equal.
	///
	/// Different underlying statistics should produce unequal status instances.
	@Test("Status instances with different statistics are not equal")
	func statusInstancesWithDifferentStatisticsAreNotEqual() {
		let bridgeStats1 = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 30,
				transmittedBytes: 1024,
				receivedBytes: 2048,
				estimatedLoss: 0.05,
				estimatedRoundTripTime: 50
			)
		)

		let bridgeStats2 = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 60,
				transmittedBytes: 2048,
				receivedBytes: 4096,
				estimatedLoss: 0.10,
				estimatedRoundTripTime: 100
			)
		)

		let status1 = TunnelStatus(bridgeStatistics: bridgeStats1)
		let status2 = TunnelStatus(bridgeStatistics: bridgeStats2)

		#expect(status1 != status2)
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
