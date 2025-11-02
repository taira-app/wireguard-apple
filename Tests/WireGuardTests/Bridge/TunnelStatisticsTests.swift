// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTunFFI
import XCTest

@testable import WireGuard

/// Tests for TunnelStatistics type and its computed properties.
///
/// TunnelStatistics provides insight into tunnel health and performance by
/// wrapping BoringTun's stats structure. These tests verify:
/// - Correct conversion from BoringTun's C stats structure
/// - Computed properties for connection quality assessment
/// - Special value handling (-1 for uninitialized metrics)
/// - Sendable and Equatable conformance
final class TunnelStatisticsTests: XCTestCase {
	// MARK: - Initialization Tests

	/// Tests creating TunnelStatistics from BoringTun's C stats structure.
	///
	/// The initializer must correctly convert all fields from the C struct
	/// to Swift types while preserving their numeric values and semantic meaning.
	func testInitFromCStats() {
		// Create a C stats structure with typical values
		var cStats = stats()
		cStats.time_since_last_handshake = 45  // 45 seconds since handshake
		cStats.tx_bytes = 1024 * 1024  // 1 MB transmitted
		cStats.rx_bytes = 2048 * 1024  // 2 MB received
		cStats.estimated_loss = 0.01  // 1% packet loss
		cStats.estimated_rtt = 50  // 50ms RTT

		let statistics = TunnelStatistics(cStats: cStats)

		// Verify all fields are correctly converted
		XCTAssertEqual(statistics.timeSinceLastHandshake, 45)
		XCTAssertEqual(statistics.transmittedBytes, 1024 * 1024)
		XCTAssertEqual(statistics.receivedBytes, 2048 * 1024)
		XCTAssertEqual(statistics.estimatedLoss, 0.01, accuracy: 0.0001)
		XCTAssertEqual(statistics.estimatedRTT, 50)
	}

	/// Tests special value -1 indicating no handshake has occurred.
	///
	/// When a tunnel is first created, timeSinceLastHandshake is -1 to indicate
	/// no handshake has completed yet. This is different from 0 which means a
	/// handshake just completed.
	func testNoHandshakeState() {
		var cStats = stats()
		cStats.time_since_last_handshake = -1  // No handshake yet
		cStats.tx_bytes = 0
		cStats.rx_bytes = 0
		cStats.estimated_loss = 0.0
		cStats.estimated_rtt = -1  // RTT also unknown

		let statistics = TunnelStatistics(cStats: cStats)

		XCTAssertEqual(statistics.timeSinceLastHandshake, -1)
		XCTAssertEqual(statistics.estimatedRTT, -1)
	}

	// MARK: - Computed Property Tests

	/// Tests hasHandshake computed property.
	///
	/// hasHandshake returns true when timeSinceLastHandshake >= 0, indicating
	/// at least one handshake has completed. This is used to determine if the
	/// tunnel is operational.
	func testHasHandshake() {
		// No handshake yet
		var cStats1 = stats()
		cStats1.time_since_last_handshake = -1
		let stats1 = TunnelStatistics(cStats: cStats1)
		XCTAssertFalse(stats1.hasHandshake, "Should not have handshake when time is -1")

		// Handshake just completed
		var cStats2 = stats()
		cStats2.time_since_last_handshake = 0
		let stats2 = TunnelStatistics(cStats: cStats2)
		XCTAssertTrue(stats2.hasHandshake, "Should have handshake when time is 0")

		// Handshake completed some time ago
		var cStats3 = stats()
		cStats3.time_since_last_handshake = 45
		let stats3 = TunnelStatistics(cStats: cStats3)
		XCTAssertTrue(stats3.hasHandshake, "Should have handshake when time is positive")
	}

	/// Tests isHandshakeStale computed property.
	///
	/// WireGuard considers a handshake stale after 180 seconds. A stale handshake
	/// indicates the connection should rekey to maintain forward secrecy.
	func testIsHandshakeStale() {
		// No handshake - not stale (need handshake first)
		var cStats1 = stats()
		cStats1.time_since_last_handshake = -1
		let stats1 = TunnelStatistics(cStats: cStats1)
		XCTAssertFalse(stats1.isHandshakeStale, "No handshake should not be stale")

		// Fresh handshake - not stale
		var cStats2 = stats()
		cStats2.time_since_last_handshake = 45
		let stats2 = TunnelStatistics(cStats: cStats2)
		XCTAssertFalse(stats2.isHandshakeStale, "45 seconds should not be stale")

		// Exactly 180 seconds - not stale (boundary)
		var cStats3 = stats()
		cStats3.time_since_last_handshake = 180
		let stats3 = TunnelStatistics(cStats: cStats3)
		XCTAssertFalse(stats3.isHandshakeStale, "180 seconds should not be stale yet")

		// 181 seconds - stale
		var cStats4 = stats()
		cStats4.time_since_last_handshake = 181
		let stats4 = TunnelStatistics(cStats: cStats4)
		XCTAssertTrue(stats4.isHandshakeStale, "181 seconds should be stale")

		// Much older - definitely stale
		var cStats5 = stats()
		cStats5.time_since_last_handshake = 300
		let stats5 = TunnelStatistics(cStats: cStats5)
		XCTAssertTrue(stats5.isHandshakeStale, "300 seconds should be stale")
	}

	/// Tests hasRTT computed property.
	///
	/// hasRTT returns true when estimatedRTT >= 0, indicating that at least
	/// one handshake has completed and RTT was measured.
	func testHasRTT() {
		// No RTT measurement yet
		var cStats1 = stats()
		cStats1.estimated_rtt = -1
		let stats1 = TunnelStatistics(cStats: cStats1)
		XCTAssertFalse(stats1.hasRTT, "Should not have RTT when value is -1")

		// RTT is 0ms (very fast local connection)
		var cStats2 = stats()
		cStats2.estimated_rtt = 0
		let stats2 = TunnelStatistics(cStats: cStats2)
		XCTAssertTrue(stats2.hasRTT, "Should have RTT when value is 0")

		// Normal RTT
		var cStats3 = stats()
		cStats3.estimated_rtt = 50
		let stats3 = TunnelStatistics(cStats: cStats3)
		XCTAssertTrue(stats3.hasRTT, "Should have RTT when value is positive")
	}

	/// Tests qualityDescription computed property.
	///
	/// qualityDescription provides a human-readable assessment of connection
	/// quality based on estimated packet loss. This is useful for displaying
	/// connection status to users.
	func testQualityDescription() {
		// Excellent: < 1% loss
		var cStats1 = stats()
		cStats1.estimated_loss = 0.005  // 0.5% loss
		let stats1 = TunnelStatistics(cStats: cStats1)
		XCTAssertEqual(stats1.qualityDescription, "Excellent")

		// Good: 1-5% loss
		var cStats2 = stats()
		cStats2.estimated_loss = 0.03  // 3% loss
		let stats2 = TunnelStatistics(cStats: cStats2)
		XCTAssertEqual(stats2.qualityDescription, "Good")

		// Fair: 5-10% loss
		var cStats3 = stats()
		cStats3.estimated_loss = 0.07  // 7% loss
		let stats3 = TunnelStatistics(cStats: cStats3)
		XCTAssertEqual(stats3.qualityDescription, "Fair")

		// Poor: >= 10% loss
		var cStats4 = stats()
		cStats4.estimated_loss = 0.15  // 15% loss
		let stats4 = TunnelStatistics(cStats: cStats4)
		XCTAssertEqual(stats4.qualityDescription, "Poor")

		// Test boundary cases
		var cStats5 = stats()
		cStats5.estimated_loss = 0.01  // Exactly 1% - should be "Good"
		let stats5 = TunnelStatistics(cStats: cStats5)
		XCTAssertEqual(stats5.qualityDescription, "Good")

		var cStats6 = stats()
		cStats6.estimated_loss = 0.05  // Exactly 5% - should be "Fair"
		let stats6 = TunnelStatistics(cStats: cStats6)
		XCTAssertEqual(stats6.qualityDescription, "Fair")

		var cStats7 = stats()
		cStats7.estimated_loss = 0.10  // Exactly 10% - should be "Poor"
		let stats7 = TunnelStatistics(cStats: cStats7)
		XCTAssertEqual(stats7.qualityDescription, "Poor")
	}

	// MARK: - Sendable Conformance Tests

	/// Tests that TunnelStatistics conforms to Sendable protocol.
	///
	/// TunnelStatistics must be Sendable because it's returned from actor
	/// methods in BoringTunBridge. This test verifies it can cross actor
	/// boundaries without data races.
	func testSendableConformance() async {
		// Create statistics in one isolation domain
		var cStats = stats()
		cStats.time_since_last_handshake = 45
		cStats.tx_bytes = 1000
		cStats.rx_bytes = 2000
		cStats.estimated_loss = 0.01
		cStats.estimated_rtt = 50
		let statistics = TunnelStatistics(cStats: cStats)

		// Send to another isolation domain
		await Task {
			// If this compiles without Sendable warnings, conformance is correct
			let _ = statistics
		}.value
	}

	// MARK: - Equatable Tests

	/// Tests that TunnelStatistics implements Equatable correctly.
	///
	/// Equatable is important for comparing statistics in tests and for
	/// detecting changes in tunnel state. Two statistics are equal only if
	/// all their fields match exactly.
	func testEquality() {
		// Create two identical statistics
		var cStats1 = stats()
		cStats1.time_since_last_handshake = 45
		cStats1.tx_bytes = 1000
		cStats1.rx_bytes = 2000
		cStats1.estimated_loss = 0.01
		cStats1.estimated_rtt = 50

		var cStats2 = stats()
		cStats2.time_since_last_handshake = 45
		cStats2.tx_bytes = 1000
		cStats2.rx_bytes = 2000
		cStats2.estimated_loss = 0.01
		cStats2.estimated_rtt = 50

		let stats1 = TunnelStatistics(cStats: cStats1)
		let stats2 = TunnelStatistics(cStats: cStats2)

		// Identical statistics are equal
		XCTAssertEqual(stats1, stats2)

		// Different timeSinceLastHandshake
		var cStats3 = stats()
		cStats3.time_since_last_handshake = 60  // Different
		cStats3.tx_bytes = 1000
		cStats3.rx_bytes = 2000
		cStats3.estimated_loss = 0.01
		cStats3.estimated_rtt = 50
		let stats3 = TunnelStatistics(cStats: cStats3)

		XCTAssertNotEqual(stats1, stats3)

		// Different transmittedBytes
		var cStats4 = stats()
		cStats4.time_since_last_handshake = 45
		cStats4.tx_bytes = 2000  // Different
		cStats4.rx_bytes = 2000
		cStats4.estimated_loss = 0.01
		cStats4.estimated_rtt = 50
		let stats4 = TunnelStatistics(cStats: cStats4)

		XCTAssertNotEqual(stats1, stats4)
	}
}
