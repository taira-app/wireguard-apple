// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

// MARK: - Computed properties

extension TunnelStatus {
	/// Whether a handshake has successfully completed.
	///
	/// Returns `true` if `lastHandshakeTime` is non-nil, indicating that at
	/// least one handshake has occurred since the tunnel was created.
	public var hasHandshake: Bool {
		lastHandshakeTime != nil
	}

	/// Whether the handshake is stale and should be rekeyed.
	///
	/// WireGuard considers a handshake stale after 180 seconds. If this returns
	/// `true`, the tunnel should initiate a rekey to maintain forward secrecy.
	public var isHandshakeStale: Bool {
		guard let lastHandshake = lastHandshakeTime else {
			return false
		}
		let timeSince = Date().timeIntervalSince(lastHandshake)
		return timeSince > 180
	}

	/// Whether RTT has been measured.
	///
	/// Returns `true` if `estimatedRTT` is non-nil, indicating that at least
	/// one handshake has completed and timing was measured.
	public var hasRTT: Bool {
		estimatedRTT != nil
	}

	/// A formatted string describing the connection quality based on packet loss.
	///
	/// This provides a simple quality indicator suitable for displaying in UI
	/// or logging connection health.
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

	/// A formatted string for transmitted bytes in human-readable units.
	///
	/// This converts the byte count to appropriate binary units (KiB, MiB, GiB)
	/// using 1024 as the divisor, following IEC 60027-2 standard.
	///
	/// ## Example output
	/// - "1.5 KiB"
	/// - "234.7 MiB"
	/// - "1.2 GiB"
	public var formattedTransmittedBytes: String {
		formatBytes(transmittedBytes)
	}

	/// A formatted string for received bytes in human-readable units.
	///
	/// This converts the byte count to appropriate binary units (KiB, MiB, GiB)
	/// using 1024 as the divisor, following IEC 60027-2 standard.
	///
	/// ## Example output
	/// - "1.5 KiB"
	/// - "234.7 MiB"
	/// - "1.2 GiB"
	public var formattedReceivedBytes: String {
		formatBytes(receivedBytes)
	}

	/// A formatted string for estimated RTT in milliseconds.
	///
	/// This converts the RTT from seconds to milliseconds and formats it
	/// with one decimal place for display.
	///
	/// ## Example output
	/// - "45.2 ms"
	/// - "Not measured" (if no RTT available)
	public var formattedRTT: String {
		guard let rtt = estimatedRTT else {
			return "Not measured"
		}

		let milliseconds = rtt * 1000.0

		return String(format: "%.1f ms", milliseconds)
	}

	/// A formatted string for estimated packet loss as a percentage.
	///
	/// This converts the loss fraction to a percentage with one decimal place.
	///
	/// ## Example output
	/// - "0.0%"
	/// - "2.5%"
	/// - "15.3%"
	public var formattedLoss: String {
		String(format: "%.1f%%", estimatedLoss * 100)
	}

	/// A formatted string for time since last handshake.
	///
	/// This provides a human-readable duration string showing how long ago
	/// the last handshake occurred.
	///
	/// ## Example output
	/// - "5 seconds ago"
	/// - "2 minutes ago"
	/// - "Never" (if no handshake has occurred)
	public var formattedTimeSinceHandshake: String {
		guard let lastHandshake = lastHandshakeTime else {
			return "Never"
		}
		let timeSince = Date().timeIntervalSince(lastHandshake)
		return formatDuration(timeSince)
	}

	// MARK: - Private formatting helpers

	/// Formats a byte count into a human-readable string with appropriate binary units.
	///
	/// This helper converts raw byte counts to KiB (kibibytes), MiB (mebibytes),
	/// or GiB (gibibytes) as appropriate, using 1024 as the divisor according to
	/// IEC 60027-2 standard for binary prefixes.
	///
	/// - Parameter bytes: The number of bytes to format
	/// - Returns: A formatted string with binary units (e.g., "1.5 MiB")
	private func formatBytes(_ bytes: UInt64) -> String {
		let kibibyte: Double = 1024
		let mebibyte = kibibyte * 1024
		let gibibyte = mebibyte * 1024

		let bytesDouble = Double(bytes)

		if bytesDouble >= gibibyte {
			return String(format: "%.1f GiB", bytesDouble / gibibyte)
		} else if bytesDouble >= mebibyte {
			return String(format: "%.1f MiB", bytesDouble / mebibyte)
		} else if bytesDouble >= kibibyte {
			return String(format: "%.1f KiB", bytesDouble / kibibyte)
		} else {
			return "\(bytes) B"
		}
	}

	/// Formats a time duration into a human-readable string.
	///
	/// This helper converts a duration in seconds to a friendly string like
	/// "5 seconds ago" or "2 minutes ago".
	///
	/// - Parameter duration: The duration in seconds
	/// - Returns: A formatted string describing the duration
	private func formatDuration(_ duration: TimeInterval) -> String {
		if duration < 60 {
			return "\(Int(duration)) seconds ago"
		} else if duration < 3600 {
			let minutes = Int(duration / 60)
			return "\(minutes) minute\(minutes == 1 ? "" : "s") ago"
		} else {
			let hours = Int(duration / 3600)
			return "\(hours) hour\(hours == 1 ? "" : "s") ago"
		}
	}
}
