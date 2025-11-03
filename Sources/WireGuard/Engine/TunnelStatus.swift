// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// High-level tunnel status information with Swift-friendly types.
///
/// This wraps the lower-level `Bridge.TunnelStatistics` and provides a more
/// ergonomic Swift API by converting low-level numeric types to Foundation types
/// like `Date` and `TimeInterval`. This makes the statistics easier to work with
/// in Swift code while maintaining access to the underlying raw values.
///
/// ## Key metrics
///
/// - **Handshake timing**: `lastHandshakeTime` provides a `Date` for the most recent handshake
/// - **Data transfer**: `transmittedBytes` and `receivedBytes` track total bandwidth usage
/// - **Network quality**: `estimatedLoss` and `estimatedRTT` indicate connection quality
///
/// ## Example usage
///
/// ```swift
/// let status = try await tunnel.status()
///
/// if let lastHandshake = status.lastHandshakeTime {
///     let timeSince = Date().timeIntervalSince(lastHandshake)
///     if timeSince > 180 {
///         logger.warning("Handshake is stale (\(timeSince)s old)")
///     }
/// }
///
/// if status.estimatedLoss > 0.1 {
///     logger.warning("High packet loss: \(status.estimatedLoss * 100)%")
/// }
/// ```
public struct TunnelStatus: Sendable, Equatable {
	/// The underlying low-level statistics from the bridge layer.
	///
	/// This provides access to the raw BoringTun statistics for cases where
	/// the original numeric values are needed. Most code should use the computed
	/// properties instead, which provide more convenient Swift types.
	internal let bridgeStatistics: TunnelStatistics

	/// Total number of bytes transmitted through the tunnel.
	///
	/// This counts only the decrypted payload bytes (actual IP packets), not
	/// the WireGuard protocol overhead. This value increases monotonically and
	/// never resets while the tunnel is active.
	public var transmittedBytes: UInt64 {
		UInt64(bridgeStatistics.transmittedBytes)
	}

	/// Total number of bytes received through the tunnel.
	///
	/// This counts only the decrypted payload bytes (actual IP packets), not
	/// the WireGuard protocol overhead. This value increases monotonically and
	/// never resets while the tunnel is active.
	public var receivedBytes: UInt64 {
		UInt64(bridgeStatistics.receivedBytes)
	}

	/// Estimated packet loss as a fraction between 0.0 and 1.0.
	///
	/// BoringTun estimates packet loss by tracking gaps in sequence numbers.
	/// This is an approximation and may not be perfectly accurate, especially
	/// over short time periods.
	///
	/// ## Interpretation
	/// - **0.0**: No packet loss detected
	/// - **0.01-0.05**: Minor loss, acceptable for most applications
	/// - **0.05-0.10**: Moderate loss, may affect quality of service
	/// - **0.10+**: High loss, connection quality is poor
	public var estimatedLoss: Float {
		bridgeStatistics.estimatedLoss
	}

	/// The timestamp of the last successful handshake, or nil if no handshake has occurred.
	///
	/// This converts the bridge's `timeSinceLastHandshake` (seconds since handshake)
	/// into an absolute `Date` value. Returns `nil` if the value is negative,
	/// indicating no handshake has completed yet.
	///
	/// WireGuard initiates a new handshake after 120 seconds under load. If this
	/// timestamp is more than 180 seconds in the past, the connection may be
	/// experiencing issues and should be monitored.
	public var lastHandshakeTime: Date? {
		guard bridgeStatistics.timeSinceLastHandshake >= 0 else {
			return nil
		}
		return Date().addingTimeInterval(-TimeInterval(bridgeStatistics.timeSinceLastHandshake))
	}

	/// Estimated round-trip time in seconds, or nil if not yet measured.
	///
	/// This converts the bridge's `estimatedRTT` (milliseconds as Int32) into
	/// a Swift `TimeInterval` (seconds as Double). Returns `nil` if the value
	/// is negative, indicating RTT has not been measured yet.
	///
	/// The RTT is measured during handshakes, so it may not reflect real-time
	/// latency between handshakes.
	///
	/// ## Interpretation
	/// - **0.0-0.05s**: Excellent (local network or nearby server)
	/// - **0.05-0.15s**: Good (typical internet)
	/// - **0.15-0.30s**: Fair (long distance or mobile network)
	/// - **0.30s+**: Poor (high latency connection)
	public var estimatedRTT: TimeInterval? {
		guard bridgeStatistics.estimatedRTT >= 0 else {
			return nil
		}
		// Convert milliseconds to seconds
		return TimeInterval(bridgeStatistics.estimatedRTT) / 1000.0
	}

	/// Creates tunnel status from low-level bridge statistics.
	///
	/// This initializer wraps the bridge statistics and provides computed properties
	/// that convert the low-level numeric types to more convenient Swift types.
	///
	/// - Parameter bridgeStatistics: The low-level statistics from BoringTun bridge
	internal init(bridgeStatistics: TunnelStatistics) {
		self.bridgeStatistics = bridgeStatistics
	}
}
