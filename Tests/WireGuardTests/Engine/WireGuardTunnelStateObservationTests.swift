// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for WireGuard tunnel state observation.
///
/// These tests verify that state transitions can be observed correctly through
/// AsyncStream, supporting multiple concurrent observers.
struct WireGuardTunnelStateObservationTests {
	/// Thread-safe collector for tunnel state transitions during testing.
	///
	/// This actor provides a safe way to collect state updates from multiple
	/// concurrent observers without data races, demonstrating proper Swift 6
	/// concurrency patterns for AsyncStream consumption.
	///
	/// ## Usage Example
	///
	/// ```swift
	/// let collector = StateCollector()
	/// let task = Task {
	///     for await state in await tunnel.observeState() {
	///         await collector.append(state)
	///     }
	/// }
	/// await task.value
	/// let states = await collector.states()
	/// ```
	actor StateCollector {
		private var collectedStates: [TunnelState] = []

		/// Appends a state to the collection.
		///
		/// This method is actor-isolated, ensuring thread-safe access to the
		/// internal array even when called from multiple Tasks concurrently.
		///
		/// - Parameter state: The tunnel state to append
		func append(_ state: TunnelState) {
			collectedStates.append(state)
		}

		/// Returns all collected states.
		///
		/// - Returns: Array of tunnel states in the order they were appended
		func states() -> [TunnelState] {
			collectedStates
		}
	}

	// MARK: - State observation tests

	/// Verifies that state observation receives the current state immediately.
	///
	/// When starting state observation, the observer should receive the current
	/// state as the first value in the stream before any transitions occur.
	@Test("State observation receives current state immediately")
	func stateObservationReceivesCurrentStateImmediately() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		var receivedStates: [TunnelState] = []

		// Start observing
		let observation = await tunnel.observeState()
		var iterator = observation.makeAsyncIterator()

		// Get first state
		if let firstState = await iterator.next() {
			receivedStates.append(firstState)
		}

		// Verify we got the stopped state
		#expect(receivedStates.count == 1)
		#expect(receivedStates.first == .stopped)
	}

	/// Verifies that state observation receives all state transitions.
	///
	/// When the tunnel transitions through states, observers should receive
	/// all state changes in order: stopped → starting → connected.
	@Test("State observation receives all transitions")
	func stateObservationReceivesAllTransitions() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		let collector = StateCollector()

		// Start observing in background task
		let observationTask = Task {
			for await state in await tunnel.observeState() {
				await collector.append(state)
				// Stop collecting after we see connected state
				if state == .connected {
					break
				}
			}
		}

		// Give observation time to set up
		try await Task.sleep(nanoseconds: 10_000_000)  // 10ms

		// Start the tunnel to trigger state transitions
		try await tunnel.start()

		// Wait for observation to complete
		await observationTask.value

		// Verify we received stopped, starting, and connected states
		let receivedStates = await collector.states()
		#expect(receivedStates.count >= 3)
		#expect(receivedStates[0] == .stopped)
		#expect(receivedStates[1] == .starting)
		#expect(receivedStates[2] == .connected)
	}

	/// Verifies that multiple observers can observe simultaneously.
	///
	/// Multiple observers should each receive their own stream of state updates
	/// without interfering with each other.
	@Test("Multiple observers can observe simultaneously")
	func multipleObserversCanObserveSimultaneously() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		let collector1 = StateCollector()
		let collector2 = StateCollector()

		// Start two observers
		let task1 = Task {
			for await state in await tunnel.observeState() {
				await collector1.append(state)
				if state == .connected {
					break
				}
			}
		}

		let task2 = Task {
			for await state in await tunnel.observeState() {
				await collector2.append(state)
				if state == .connected {
					break
				}
			}
		}

		// Give observers time to set up
		try await Task.sleep(nanoseconds: 10_000_000)  // 10ms

		// Start the tunnel
		try await tunnel.start()

		// Wait for both observers
		await task1.value
		await task2.value

		// Both observers should have received the same states
		let observer1States = await collector1.states()
		let observer2States = await collector2.states()
		#expect(observer1States.count >= 3)
		#expect(observer2States.count >= 3)
		#expect(observer1States[0] == .stopped)
		#expect(observer2States[0] == .stopped)
	}
}
