// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTun
import Foundation
import Testing

@testable import WireGuard

/// Tests for tunnel status formatted output properties.
///
/// These tests verify that TunnelStatus provides user-friendly formatted strings
/// for bytes, round-trip time, loss percentage, and time since handshake. All
/// formatting should use correct binary units (KiB, MiB, GiB) and clear descriptions.
struct TunnelStatusFormattingTests {
	// MARK: - Formatted bytes tests

	/// Verifies that bytes are formatted correctly.
	///
	/// Small byte counts should be displayed as raw bytes.
	@Test("Bytes formatted correctly for small values")
	func bytesFormattedCorrectlyForSmallValues() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 512,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedTransmittedBytes == "512 B")
	}

	/// Verifies that kibibytes are formatted correctly with binary prefix.
	///
	/// Values over 1024 bytes should use KiB (kibibytes), not KB (kilobytes).
	@Test("Kibibytes formatted correctly")
	func kibibytesFormattedCorrectly() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 1536,  // 1.5 KiB
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedReceivedBytes == "1.5 KiB")
	}

	/// Verifies that mebibytes are formatted correctly with binary prefix.
	///
	/// Values over 1024^2 bytes should use MiB (mebibytes), not MB (megabytes).
	@Test("Mebibytes formatted correctly")
	func mebibytesFormattedCorrectly() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 5_242_880,  // 5 MiB
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedTransmittedBytes == "5.0 MiB")
	}

	/// Verifies that gibibytes are formatted correctly with binary prefix.
	///
	/// Values over 1024^3 bytes should use GiB (gibibytes), not GB (gigabytes).
	@Test("Gibibytes formatted correctly")
	func gibibytesFormattedCorrectly() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 2_147_483_648,  // 2 GiB
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedReceivedBytes == "2.0 GiB")
	}

	// MARK: - Formatted round-trip time tests

	/// Verifies that round-trip time is formatted as milliseconds.
	///
	/// The round-trip time should be displayed in milliseconds with one decimal place.
	@Test("Round-trip time formatted as milliseconds")
	func roundTripTimeFormattedAsMilliseconds() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: 45  // 45 ms
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedRTT == "45.0 ms")
	}

	/// Verifies that unmeasured round-trip time shows appropriate message.
	///
	/// When round-trip time has not been measured, the formatted value should indicate this.
	@Test("Unmeasured round-trip time shows not measured")
	func unmeasuredRoundTripTimeShowsNotMeasured() {
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

		#expect(status.formattedRTT == "Not measured")
	}

	// MARK: - Formatted loss tests

	/// Verifies that packet loss is formatted as a percentage.
	///
	/// The loss should be displayed as a percentage with one decimal place.
	@Test("Loss formatted as percentage")
	func lossFormattedAsPercentage() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 0,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0.0253,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedLoss == "2.5%")
	}

	// MARK: - Formatted time since handshake tests

	/// Verifies that no handshake shows appropriate message.
	///
	/// When no handshake has occurred, the formatted time should show "Never".
	@Test("No handshake shows never")
	func noHandshakeShowsNever() {
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

		#expect(status.formattedTimeSinceHandshake == "Never")
	}

	/// Verifies that recent handshake shows seconds.
	///
	/// Handshakes less than 60 seconds ago should be displayed in seconds.
	@Test("Recent handshake shows seconds")
	func recentHandshakeShowsSeconds() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 45,
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedTimeSinceHandshake == "45 seconds ago")
	}

	/// Verifies that handshake over a minute shows minutes.
	///
	/// Handshakes between 60 and 3600 seconds ago should be displayed in minutes.
	@Test("Handshake over minute shows minutes")
	func handshakeOverMinuteShowsMinutes() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 150,  // 2.5 minutes
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedTimeSinceHandshake == "2 minutes ago")
	}

	/// Verifies that handshake over an hour shows hours.
	///
	/// Handshakes over 3600 seconds ago should be displayed in hours.
	@Test("Handshake over hour shows hours")
	func handshakeOverHourShowsHours() {
		let bridgeStats = TunnelStatistics(
			cStats: createStats(
				timeSinceLastHandshake: 7200,  // 2 hours
				transmittedBytes: 0,
				receivedBytes: 0,
				estimatedLoss: 0,
				estimatedRoundTripTime: -1
			)
		)

		let status = TunnelStatus(bridgeStatistics: bridgeStats)

		#expect(status.formattedTimeSinceHandshake == "2 hours ago")
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
