// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for WireGuard tunnel initialization and lifecycle operations.
///
/// These tests verify that tunnel creation, starting, stopping, and restarting
/// all work correctly.
struct WireGuardTunnelLifecycleTests {
	// MARK: - Initialization tests

	/// Verifies that a tunnel can be created with valid configuration.
	///
	/// The tunnel should initialize successfully with a complete configuration
	/// including interface settings and at least one peer.
	@Test("Tunnel initializes with valid configuration")
	func tunnelInitializesWithValidConfiguration() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Verify initial state is stopped
		let state = await tunnel.currentTunnelState()
		#expect(state == .stopped)
	}

	// MARK: - Lifecycle tests

	/// Verifies that a tunnel can be started successfully.
	///
	/// Starting the tunnel should transition it from stopped to connected state
	/// and initialize the BoringTun bridge with the configuration.
	@Test("Tunnel starts successfully")
	func tunnelStartsSuccessfully() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start the tunnel
		try await tunnel.start()

		// Verify state is connected
		let state = await tunnel.currentTunnelState()
		#expect(state == .connected)
	}

	/// Verifies that starting an already-running tunnel throws an error.
	///
	/// Attempting to start a tunnel that's already in the connected or starting
	/// state should throw alreadyRunning error rather than creating multiple
	/// instances of the bridge or tick task.
	@Test("Starting already-running tunnel throws error")
	func startingAlreadyRunningTunnelThrowsError() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start the tunnel
		try await tunnel.start()

		// Attempt to start again
		await #expect(throws: EngineError.alreadyRunning) {
			try await tunnel.start()
		}
	}

	/// Verifies that a tunnel can be stopped successfully.
	///
	/// Stopping the tunnel should transition it from connected to stopped state,
	/// cancel the tick task, and destroy the BoringTun bridge.
	@Test("Tunnel stops successfully")
	func tunnelStopsSuccessfully() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start then stop the tunnel
		try await tunnel.start()
		await tunnel.stop()

		// Verify state is stopped
		let state = await tunnel.currentTunnelState()
		#expect(state == .stopped)
	}

	/// Verifies that stopping an already-stopped tunnel is safe.
	///
	/// Calling stop() on a stopped tunnel should be a no-op rather than
	/// causing errors or side effects.
	@Test("Stopping already-stopped tunnel is safe")
	func stoppingAlreadyStoppedTunnelIsSafe() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Stop tunnel that's already stopped
		await tunnel.stop()

		// Verify state is still stopped
		let state = await tunnel.currentTunnelState()
		#expect(state == .stopped)
	}

	/// Verifies that a tunnel can be restarted after stopping.
	///
	/// After stopping a tunnel, it should be possible to start it again,
	/// creating a fresh bridge and tick task.
	@Test("Tunnel can be restarted after stopping")
	func tunnelCanBeRestartedAfterStopping() async throws {
		let config = try TestHelpers.createTestConfiguration()
		let tunnel = try await WireGuardTunnel(configuration: config)

		// Start, stop, and restart
		try await tunnel.start()
		await tunnel.stop()
		try await tunnel.start()

		// Verify state is connected
		let state = await tunnel.currentTunnelState()
		#expect(state == .connected)
	}
}
