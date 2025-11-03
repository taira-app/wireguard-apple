// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

// MARK: - State management

extension WireGuardTunnel {
	/// Transitions the tunnel to a new state and notifies observers.
	///
	/// This method updates the current state and broadcasts the new state to all
	/// active observers via their AsyncStream continuations. State transitions
	/// should always go through this method to ensure observers are notified.
	///
	/// ## State Transition Rules
	///
	/// Normal lifecycle:
	/// - stopped → starting → connected → stopping → stopped
	///
	/// Error transitions:
	/// - any state → error
	///
	/// Recovery:
	/// - error → stopped (via stop() call)
	///
	/// - Parameter newState: The state to transition to
	internal func transitionState(to newState: TunnelState) async {
		// Update current state
		currentState = newState

		// Notify all observers
		for (_, continuation) in stateObservers {
			continuation.yield(newState)
		}
	}

	/// Removes a state observer by identifier.
	///
	/// This method is called automatically when an observation stream is terminated.
	/// It removes the observer's continuation from the active observers map, ensuring
	/// that the continuation is no longer sent state updates and can be deallocated.
	///
	/// - Parameter observerId: The unique identifier for the observer to remove
	internal func removeStateObserver(_ observerId: UUID) async {
		stateObservers.removeValue(forKey: observerId)
	}

	/// Retrieves the current tunnel state.
	///
	/// This method provides read-only access to the current state for testing
	/// and debugging purposes. For observing state changes over time, use
	/// `observeState()` instead.
	///
	/// - Returns: The current tunnel state
	public func currentTunnelState() async -> TunnelState {
		return currentState
	}
}
