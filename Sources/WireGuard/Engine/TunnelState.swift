// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Represents the current lifecycle state of a WireGuard tunnel.
///
/// The tunnel progresses through these states as it starts, runs, and stops.
/// State transitions are observable via `WireGuardTunnel.observeState()` for
/// monitoring tunnel health and coordinating UI updates.
///
/// ## State lifecycle
///
/// Normal startup:
/// ```
/// stopped → starting → connected
/// ```
///
/// Normal shutdown:
/// ```
/// connected → stopping → stopped
/// ```
///
/// Network interruption:
/// ```
/// connected → reasserting → connected
/// ```
///
/// Error condition:
/// ```
/// any state → error
/// ```
///
/// ## Example usage
///
/// ```swift
/// let tunnel = try await WireGuardTunnel(configuration: config)
///
/// for await state in tunnel.observeState() {
///     switch state {
///     case .connected:
///         print("Tunnel is ready")
///     case .error(let message):
///         print("Tunnel error: \(message)")
///     case .stopped:
///         print("Tunnel stopped")
///     default:
///         print("State: \(state.description)")
///     }
/// }
/// ```
public enum TunnelState: Sendable, Equatable {
	/// The tunnel is completely stopped and not processing packets.
	///
	/// This is the initial state after creation and the final state after
	/// shutdown completes. No resources are allocated in this state.
	case stopped

	/// The tunnel is in the process of starting up.
	///
	/// During this state, the tunnel initializes the BoringTun engine,
	/// resolves endpoints if needed, and prepares for packet processing.
	/// This is a transient state that typically lasts milliseconds.
	case starting

	/// The tunnel is active and processing packets.
	///
	/// This is the normal operating state. The tunnel encrypts outbound
	/// packets and decrypts inbound packets, and performs periodic
	/// maintenance like keepalives and handshake renewals.
	case connected

	/// The tunnel is in the process of shutting down.
	///
	/// During this state, the tunnel completes any pending operations,
	/// cleans up resources, and prepares for full shutdown. This is a
	/// transient state that typically lasts milliseconds.
	case stopping

	/// The tunnel is attempting to recover from a network interruption.
	///
	/// This state occurs when the tunnel detects a network change (such as
	/// switching between WiFi and cellular) and needs to re-establish the
	/// connection. The tunnel remains active during reassertion but may
	/// temporarily drop packets.
	case reasserting

	/// The tunnel encountered an error and cannot continue.
	///
	/// The associated string describes the error that occurred. When in this
	/// state, the tunnel should be stopped and potentially restarted with a
	/// fresh configuration.
	///
	/// - Parameter message: Human-readable error description
	case error(String)

	/// A human-readable description of the current state.
	///
	/// This is suitable for displaying in logs or debugging UI. For user-facing
	/// messages, consider providing localized strings based on the case.
	public var description: String {
		switch self {
		case .stopped:
			return "stopped"
		case .starting:
			return "starting"
		case .connected:
			return "connected"
		case .stopping:
			return "stopping"
		case .reasserting:
			return "reasserting"
		case .error(let message):
			return "error: \(message)"
		}
	}
}
