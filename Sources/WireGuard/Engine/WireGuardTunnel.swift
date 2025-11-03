// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

/// Main orchestrator for WireGuard tunnel operations.
///
/// WireGuardTunnel is the primary public API for the Engine domain. It coordinates
/// tunnel lifecycle, packet processing, and state management using the BoringTun
/// bridge and packet processor.
///
/// ## Responsibilities
///
/// - **Lifecycle management**: Starting and stopping the tunnel
/// - **Packet processing**: Encrypting outbound and decrypting inbound packets
/// - **State observation**: Broadcasting state changes to observers
/// - **Statistics**: Providing tunnel health and performance metrics
/// - **Error handling**: Converting low-level errors to user-friendly messages
///
/// ## Example usage
///
/// ```swift
/// // Create configuration
/// let privateKey = PrivateKey()
/// let peer = PeerConfiguration(publicKey: peerPublicKey)
/// peer.endpoint = Endpoint(host: .name("vpn.example.com"), port: 51820)
/// peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]
///
/// let interface = InterfaceConfiguration(privateKey: privateKey)
/// interface.addresses = [IPAddressRange(from: "10.0.0.2/24")!]
///
/// let config = TunnelConfiguration(
///     name: "MyVPN",
///     interface: interface,
///     peers: [peer]
/// )
///
/// // Create and start tunnel
/// let tunnel = try await WireGuardTunnel(configuration: config)
/// try await tunnel.start()
///
/// // Observe state changes
/// for await state in tunnel.observeState() {
///     print("Tunnel state: \(state.description)")
/// }
///
/// // Process packets
/// if let encrypted = try await tunnel.processOutboundPacket(ipPacket) {
///     // Send encrypted packet to peer
/// }
///
/// // Get statistics
/// let stats = try await tunnel.statistics()
/// print("Transmitted: \(stats.formattedTransmittedBytes)")
///
/// // Stop tunnel
/// await tunnel.stop()
/// ```
public actor WireGuardTunnel {
	/// The tunnel configuration.
	///
	/// This contains all the settings needed to establish and maintain the
	/// WireGuard connection, including keys, peers, and network settings.
	private let configuration: TunnelConfiguration

	/// The BoringTun bridge for cryptographic operations.
	///
	/// This wraps the Rust BoringTun implementation and provides the low-level
	/// FFI interface for packet processing and handshake operations.
	internal let bridge: BoringTunBridge

	/// The packet processor that coordinates encryption and decryption.
	///
	/// This actor manages packet buffers and delegates to the bridge for actual
	/// cryptographic operations.
	internal let processor: PacketProcessor

	/// The current tunnel state.
	///
	/// This tracks the lifecycle state of the tunnel (stopped, starting, connected,
	/// etc.) and is updated as operations progress.
	internal var currentState: TunnelState = .stopped

	/// State observation continuations.
	///
	/// Each observer gets a continuation that receives state updates. The UUID
	/// key allows removing observers when they're no longer needed.
	internal var stateObservers: [UUID: AsyncStream<TunnelState>.Continuation] = [:]

	/// The task that performs periodic tunnel maintenance.
	///
	/// This task calls tick() regularly to handle keepalives, timeouts, and
	/// handshake renewals. It's started when the tunnel starts and cancelled
	/// when the tunnel stops.
	internal var tickTask: Task<Void, Never>?

	/// Creates a new WireGuard tunnel with the given configuration.
	///
	/// This initializes the BoringTun bridge and packet processor, but does not
	/// start the tunnel. Call `start()` to begin processing packets.
	///
	/// The tunnel is created in the stopped state. State observation can begin
	/// immediately, but packet processing will fail until the tunnel is started.
	///
	/// - Parameter configuration: The tunnel configuration with keys and peers
	/// - Throws: EngineError.notConfigured if configuration is invalid
	public init(configuration: TunnelConfiguration) async throws {
		self.configuration = configuration
		self.bridge = BoringTunBridge()
		self.processor = PacketProcessor(bridge: bridge)

		// Initial state is stopped
		currentState = .stopped
	}

	/// Starts the tunnel and begins processing packets.
	///
	/// This method transitions the tunnel from stopped to connected state by:
	/// 1. Validating the configuration
	/// 2. Initializing the BoringTun bridge with keys and peer information
	/// 3. Starting the periodic tick task for maintenance
	/// 4. Transitioning to the connected state
	///
	/// If the tunnel is already running, this method throws alreadyRunning error.
	///
	/// - Throws: EngineError.alreadyRunning if tunnel is already started
	/// - Throws: EngineError.notConfigured if configuration is invalid
	/// - Throws: EngineError.endpointResolutionFailed if peer endpoint cannot be resolved
	public func start() async throws {
		// Check if already running
		guard currentState == .stopped else {
			throw EngineError.alreadyRunning
		}

		// Transition to starting state
		await transitionState(to: .starting)

		do {
			// Initialize bridge with configuration
			guard let peer = configuration.peers.first else {
				throw EngineError.notConfigured
			}

			try await bridge.createTunnel(
				privateKey: configuration.interface.privateKey.base64Key,
				peerPublicKey: peer.publicKey.base64Key,
				presharedKey: peer.presharedKey?.base64Key,
				keepalive: peer.persistentKeepalive.map { UInt16($0) } ?? 0
			)

			// Start periodic tick task
			startTickTask()

			// Transition to connected state
			await transitionState(to: .connected)
		} catch {
			// Transition to error state
			await transitionState(to: .error(error.localizedDescription))
			throw error
		}
	}

	/// Stops the tunnel and cleans up resources.
	///
	/// This method transitions the tunnel from connected to stopped state by:
	/// 1. Cancelling the periodic tick task
	/// 2. Destroying the BoringTun tunnel
	/// 3. Transitioning to the stopped state
	///
	/// This method is safe to call even if the tunnel is already stopped.
	public func stop() async {
		// Check if already stopped
		guard currentState != .stopped else {
			return
		}

		// Transition to stopping state
		await transitionState(to: .stopping)

		// Cancel tick task
		tickTask?.cancel()
		tickTask = nil

		// Destroy tunnel
		await bridge.destroyTunnel()

		// Transition to stopped state
		await transitionState(to: .stopped)
	}

	/// Processes an outbound IP packet for transmission to the peer.
	///
	/// This method encrypts an IP packet from the system's network stack into
	/// a WireGuard packet suitable for transmission over the network. The returned
	/// packet should be sent to the peer's endpoint via UDP.
	///
	/// The method may return nil if no packet should be sent (for example, during
	/// handshake negotiation).
	///
	/// - Parameter packet: The IP packet to encrypt
	/// - Returns: The encrypted WireGuard packet, or nil if no packet to send
	/// - Throws: EngineError.notRunning if tunnel is not started
	/// - Throws: EngineError.invalidPacket if packet is malformed
	/// - Throws: EngineError.processingFailed if encryption fails
	public func processOutboundPacket(_ packet: Data) async throws -> Data? {
		guard currentState == .connected else {
			throw EngineError.notRunning
		}

		return try await processor.processOutbound(packet)
	}

	/// Processes an inbound network packet from the peer.
	///
	/// This method decrypts a WireGuard packet received from the peer and returns
	/// a result containing both:
	/// - Any decrypted IP packet to inject into the system's network stack
	/// - Any response packet that must be sent back to the peer (e.g., handshake response)
	///
	/// When using this in a NetworkExtension, both outputs must be handled:
	/// - Decrypted packets should be written to the tunnel interface
	/// - Response packets must be sent to the peer via UDP
	///
	/// Failing to send response packets will cause handshakes to fail and prevent
	/// the tunnel from establishing a connection.
	///
	/// - Parameter packet: The encrypted WireGuard packet from the peer
	/// - Returns: Decrypted packet (if any) and response to send (if any)
	/// - Throws: EngineError.notRunning if tunnel is not started
	/// - Throws: EngineError.invalidPacket if packet is malformed
	/// - Throws: EngineError.processingFailed if decryption fails
	public func processInboundPacket(_ packet: Data) async throws -> (
		decryptedPacket: (Data, isIPv4: Bool)?,
		responseToSend: Data?
	) {
		guard currentState == .connected else {
			throw EngineError.notRunning
		}

		let result = try await processor.processInbound(packet)
		return (decryptedPacket: result.decryptedPacket, responseToSend: result.packetToSend)
	}

	/// Retrieves current tunnel statistics.
	///
	/// This method queries the BoringTun bridge for current tunnel health and
	/// performance metrics, including handshake timing, byte counts, and network
	/// quality indicators.
	///
	/// Statistics can be retrieved at any time, even if the tunnel is not running.
	/// However, they will only be meaningful after the tunnel has been started.
	///
	/// - Returns: Current tunnel statistics
	/// - Throws: EngineError.processingFailed if statistics retrieval fails
	public func statistics() async throws -> TunnelStatus {
		return try await processor.statistics()
	}

	/// Observes tunnel state changes.
	///
	/// This method returns an AsyncStream that emits the current state and all
	/// future state transitions. The stream will continue until the observation
	/// is cancelled or the tunnel is deallocated.
	///
	/// Multiple observers can be active simultaneously, each receiving their own
	/// stream of state updates.
	///
	/// ## Example usage
	///
	/// ```swift
	/// for await state in tunnel.observeState() {
	///     switch state {
	///     case .connected:
	///         print("Tunnel connected")
	///     case .error(let message):
	///         print("Tunnel error: \(message)")
	///     default:
	///         print("State: \(state.description)")
	///     }
	/// }
	/// ```
	///
	/// - Returns: An async stream of tunnel state updates
	public func observeState() -> AsyncStream<TunnelState> {
		let observerId = UUID()

		return AsyncStream { continuation in
			// Send current state immediately
			continuation.yield(currentState)

			// Store continuation for future updates
			stateObservers[observerId] = continuation

			// Remove continuation when stream is terminated
			continuation.onTermination = { [weak self] _ in
				Task { [weak self] in
					await self?.removeStateObserver(observerId)
				}
			}
		}
	}

	/// Cleans up resources when the tunnel is deallocated.
	///
	/// This ensures the tunnel is properly stopped and all resources are released.
	deinit {
		// Cancel tick task if running
		tickTask?.cancel()
	}
}
