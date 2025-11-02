// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import BoringTunFFI
import Foundation

/// Statistics about a WireGuard tunnel's operation.
///
/// These metrics provide insight into the tunnel's health, performance, and
/// network quality. They're useful for monitoring, debugging, and displaying
/// connection status to users.
///
/// Statistics are retrieved by calling `wireguard_stats()` on an active tunnel
/// and are updated continuously as the tunnel processes packets.
///
/// ## Key Metrics
///
/// - **Handshake timing**: How long since the last successful key exchange
/// - **Data transfer**: Total bytes sent and received (payload only)
/// - **Network quality**: Estimated packet loss and round-trip time
///
/// ## Example Usage
///
/// ```swift
/// let stats = try await bridge.statistics()
///
/// if stats.timeSinceLastHandshake > 180 {
///     // Handshake is stale, connection may be dead
///     logger.warning("No handshake in \(stats.timeSinceLastHandshake) seconds")
/// }
///
/// if stats.estimatedLoss > 0.1 {
///     // More than 10% packet loss
///     logger.warning("High packet loss: \(stats.estimatedLoss * 100)%")
/// }
/// ```
public struct TunnelStatistics: Sendable, Equatable {
	/// Time elapsed since the last successful handshake, in seconds.
	///
	/// This value increases monotonically from the moment a handshake completes
	/// and resets to 0 when a new handshake succeeds.
	///
	/// ## Special Values
	/// - **-1**: No handshake has occurred yet (tunnel just created)
	/// - **0-179**: Handshake is fresh, connection is healthy
	/// - **180+**: Handshake is stale, WireGuard will attempt rekey
	///
	/// WireGuard initiates a new handshake after 120 seconds under load, or
	/// uses keepalives to maintain the session. If this value exceeds 180 seconds,
	/// the connection may be experiencing issues.
	public let timeSinceLastHandshake: Int64

	/// Total number of bytes transmitted through the tunnel.
	///
	/// This counts only the decrypted payload bytes (the actual IP packets),
	/// not the WireGuard protocol overhead (encryption, authentication tags,
	/// headers). It represents the application-layer data sent through the tunnel.
	///
	/// This value increases monotonically and never resets while the tunnel
	/// is active. It's useful for bandwidth monitoring and quota tracking.
	public let transmittedBytes: UInt

	/// Total number of bytes received through the tunnel.
	///
	/// This counts only the decrypted payload bytes (the actual IP packets),
	/// not the WireGuard protocol overhead. It represents the application-layer
	/// data received through the tunnel.
	///
	/// This value increases monotonically and never resets while the tunnel
	/// is active. It's useful for bandwidth monitoring and quota tracking.
	public let receivedBytes: UInt

	/// Estimated packet loss as a fraction between 0.0 and 1.0.
	///
	/// BoringTun estimates packet loss by tracking gaps in sequence numbers
	/// of received packets. This is an approximation and may not be perfectly
	/// accurate, especially over short time periods.
	///
	/// ## Interpretation
	/// - **0.0**: No packet loss detected
	/// - **0.01-0.05**: Minor loss, acceptable for most applications
	/// - **0.05-0.10**: Moderate loss, may affect quality of service
	/// - **0.10+**: High loss, connection quality is poor
	///
	/// Note that some loss is normal on unreliable networks (cellular, WiFi),
	/// but sustained high loss indicates network issues.
	public let estimatedLoss: Float

	/// Estimated round-trip time in milliseconds.
	///
	/// This is measured by timing how long it takes to complete a handshake,
	/// which involves a round-trip exchange with the peer. It serves as a proxy
	/// for network latency.
	///
	/// ## Special Values
	/// - **-1**: RTT cannot be estimated (no handshake completed yet)
	/// - **0-50ms**: Excellent (local network or nearby server)
	/// - **50-150ms**: Good (typical internet)
	/// - **150-300ms**: Fair (long distance or mobile network)
	/// - **300ms+**: Poor (high latency connection)
	///
	/// This value is only updated when a handshake completes, so it may not
	/// reflect real-time changes in network latency between handshakes.
	public let estimatedRTT: Int32

	/// Creates tunnel statistics from BoringTun's C FFI statistics structure.
	///
	/// This converts the C `stats` struct into a Swift-native type, translating
	/// all numeric fields while preserving their semantic meaning. The C structure
	/// is a simple aggregate of numeric values with no pointer fields.
	///
	/// - Parameter cStats: The C statistics structure from `wireguard_stats()`.
	internal init(cStats: stats) {
		self.timeSinceLastHandshake = cStats.time_since_last_handshake
		self.transmittedBytes = UInt(cStats.tx_bytes)
		self.receivedBytes = UInt(cStats.rx_bytes)
		self.estimatedLoss = cStats.estimated_loss
		self.estimatedRTT = cStats.estimated_rtt
	}
}

// MARK: - Computed Properties

extension TunnelStatistics {
	/// Whether a handshake has successfully completed.
	///
	/// Returns `true` if `timeSinceLastHandshake` is non-negative, indicating
	/// that at least one handshake has occurred since the tunnel was created.
	public var hasHandshake: Bool {
		timeSinceLastHandshake >= 0
	}

	/// Whether the handshake is stale and should be rekeyed.
	///
	/// WireGuard considers a handshake stale after 180 seconds. If this returns
	/// `true`, the tunnel should initiate a rekey to maintain forward secrecy.
	public var isHandshakeStale: Bool {
		guard hasHandshake else { return false }
		return timeSinceLastHandshake > 180
	}

	/// Whether RTT has been measured.
	///
	/// Returns `true` if `estimatedRTT` is non-negative, indicating that at
	/// least one handshake has completed and timing was measured.
	public var hasRTT: Bool {
		estimatedRTT >= 0
	}

	/// A formatted string describing the connection quality based on packet loss.
	///
	/// - Returns: "Excellent", "Good", "Fair", or "Poor"
	public var qualityDescription: String {
		if estimatedLoss < 0.01 {
			return "Excellent"
		} else if estimatedLoss < 0.05 {
			return "Good"
		} else if estimatedLoss < 0.10 {
			return "Fair"
		} else {
			return "Poor"
		}
	}
}
