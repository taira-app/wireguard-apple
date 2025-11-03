import NetworkExtension

#if false  // This is an example file, not compiled into the library.

	/// Example implementation of NEPacketTunnelProvider using TairaWireGuard.
	///
	/// This class demonstrates how to integrate TairaWireGuard into a NetworkExtension
	/// packet tunnel provider. You can copy this code as a starting point for your own
	/// VPN application.
	///
	/// # Overview
	///
	/// A VPN application on iOS or macOS consists of two parts:
	/// 1. The main application (configures and starts the VPN)
	/// 2. The network extension (runs the actual VPN tunnel)
	///
	/// This example shows the network extension side. It handles:
	/// - Loading WireGuard configuration
	/// - Starting the tunnel
	/// - Processing packets
	/// - Handling tunnel lifecycle
	///
	/// # Setup
	///
	/// To use this in your project:
	/// 1. Create a Network Extension target in Xcode
	/// 2. Create a subclass of NEPacketTunnelProvider (like this example)
	/// 3. Add TairaWireGuard as a dependency to your extension target
	/// 4. Configure your extension's Info.plist
	/// 5. Request VPN entitlements from Apple
	///
	/// # Note
	///
	/// This is a simplified example. Production implementations should include:
	/// - Error handling and recovery
	/// - Logging and diagnostics
	/// - Connection monitoring
	/// - Graceful shutdown handling
	final class ExamplePacketTunnelProvider: NEPacketTunnelProvider {

		/// The WireGuard tunnel instance that handles encryption/decryption.
		///
		/// This is the core of our VPN. It encrypts outbound packets from the device
		/// and decrypts inbound packets from the network.
		private var tunnel: WireGuardTunnel?

		/// Task that reads packets from the device and sends them through the tunnel.
		///
		/// This runs continuously while the VPN is connected, processing all network
		/// traffic from the device.
		private var outboundTask: Task<Void, Never>?

		/// Task that reads packets from the network and delivers them to the device.
		///
		/// This also runs continuously, processing incoming network traffic.
		private var inboundTask: Task<Void, Never>?

		// MARK: - Tunnel lifecycle

		/// Called when the system wants to start the VPN tunnel.
		///
		/// This is the main entry point for starting the VPN. The system calls this
		/// when the user enables the VPN from Settings or when your app calls
		/// startVPNTunnel() on the tunnel manager.
		///
		/// - Parameter options: Optional configuration passed from the app (not used here)
		/// - Parameter completionHandler: Call this when startup is complete or if it fails
		override func startTunnel(
			options: [String: NSObject]?,
			completionHandler: @escaping (Error?) -> Void
		) {
			// Start the tunnel asynchronously.
			// We use a Task because startTunnel's completion handler predates async/await.
			Task {
				do {
					try await startTunnelAsync()
					completionHandler(nil)
				} catch {
					completionHandler(error)
				}
			}
		}

		/// Async implementation of tunnel startup.
		///
		/// This is where the actual work happens. We:
		/// 1. Load the WireGuard configuration
		/// 2. Generate NetworkExtension settings
		/// 3. Create the WireGuard tunnel
		/// 4. Start packet processing
		private func startTunnelAsync() async throws {
			// Step 1: Load WireGuard configuration.
			// In a real app, this would come from your app's shared storage or be
			// passed via the tunnel's protocolConfiguration.
			let configuration = try loadConfiguration()

			// Step 2: Generate NetworkExtension settings.
			// We need to tell NetworkExtension what IP addresses, routes, and DNS
			// servers to use for the tunnel.
			let tunnelRemoteAddress = configuration.peers.first?.endpoint?.host.stringValue ?? "0.0.0.0"
			let generator = TunnelSettingsGenerator(
				configuration: configuration,
				tunnelRemoteAddress: tunnelRemoteAddress
			)
			let settings = try generator.generateNetworkSettings()

			// Apply the settings to the tunnel.
			// This configures the virtual network interface.
			try await setTunnelNetworkSettings(settings)

			// Step 3: Create the WireGuard tunnel.
			// This initializes the BoringTun engine with our configuration.
			let tunnel = try await WireGuardTunnel(configuration: configuration)
			self.tunnel = tunnel

			// Step 4: Start packet processing tasks.
			// We need two tasks: one for outbound traffic (device → network)
			// and one for inbound traffic (network → device).
			await startPacketProcessing()
		}

		/// Starts the packet processing tasks.
		///
		/// This creates two concurrent tasks:
		/// - Outbound: Reads packets from device, encrypts them, sends to network
		/// - Inbound: Reads packets from network, decrypts them, delivers to device
		private func startPacketProcessing() async {
			guard let tunnel = self.tunnel else {
				return
			}

			// Start outbound processing (device → network).
			outboundTask = Task {
				await processOutboundPackets(tunnel: tunnel)
			}

			// Start inbound processing (network → device).
			inboundTask = Task {
				await processInboundPackets(tunnel: tunnel)
			}
		}

		/// Processes packets from the device to the network.
		///
		/// This reads IP packets from the device (via packetFlow), encrypts them
		/// using WireGuard, and sends the encrypted packets to the network.
		private func processOutboundPackets(tunnel: WireGuardTunnel) async {
			// Create a stream of packets from the device.
			let stream = PacketFlowAdapter.readPackets(from: packetFlow)

			// Process each batch of packets.
			for await packets in stream {
				for packet in packets {
					do {
						// Encrypt the packet using WireGuard.
						// This returns the encrypted packet ready to send to the network,
						// or nil if the packet should be dropped.
						if let encryptedPacket = try await tunnel.processOutboundPacket(packet) {
							// Send the encrypted packet to the network.
							// In a real implementation, you would send this via UDP to
							// the peer's endpoint.
							// For simplicity, this example doesn't show the UDP socket code.
							_ = encryptedPacket
						}
					} catch {
						// Packet processing failed.
						// In production, you might log this or collect statistics.
						continue
					}
				}
			}
		}

		/// Processes packets from the network to the device.
		///
		/// This receives encrypted packets from the network, decrypts them using
		/// WireGuard, and delivers the decrypted IP packets to the device.
		private func processInboundPackets(tunnel: WireGuardTunnel) async {
			// In a real implementation, this would read from a UDP socket.
			// For this example, we'll show the packet processing logic.

			// Imagine we received an encrypted packet from the network:
			// let encryptedPacket = receiveFromUDP()  // Not shown

			// Process the encrypted packet.
			// do {
			//     // Decrypt the packet using WireGuard.
			//     if let (decryptedPacket, isIPv4) = try await tunnel.processInboundPacket(encryptedPacket) {
			//         // Write the decrypted packet to the device.
			//         try await PacketFlowAdapter.writePacket(decryptedPacket, to: packetFlow)
			//     }
			// } catch {
			//     // Decryption failed (invalid packet, authentication failed, etc.)
			// }
		}

		/// Called when the system wants to stop the VPN tunnel.
		///
		/// This is called when the user disables the VPN or when your app calls
		/// stopVPNTunnel() on the tunnel manager.
		///
		/// - Parameter reason: Why the tunnel is being stopped
		/// - Parameter completionHandler: Call this when shutdown is complete
		override func stopTunnel(
			with reason: NEProviderStopReason,
			completionHandler: @escaping () -> Void
		) {
			// Stop the tunnel asynchronously.
			Task {
				await stopTunnelAsync()
				completionHandler()
			}
		}

		/// Async implementation of tunnel shutdown.
		///
		/// This stops packet processing and cleans up resources.
		private func stopTunnelAsync() async {
			// Cancel the packet processing tasks.
			outboundTask?.cancel()
			inboundTask?.cancel()
			outboundTask = nil
			inboundTask = nil

			// Stop the WireGuard tunnel.
			if let tunnel = self.tunnel {
				await tunnel.stop()
				self.tunnel = nil
			}
		}

		// MARK: - Configuration loading

		/// Loads the WireGuard configuration.
		///
		/// In a real app, you would load this from:
		/// - Shared app group container
		/// - Tunnel's protocolConfiguration
		/// - Keychain
		///
		/// This example shows a hardcoded configuration for demonstration.
		private func loadConfiguration() throws -> TunnelConfiguration {
			// Create interface configuration.
			let privateKey = PrivateKey()
			var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

			// Configure interface IP address.
			let address = try IPAddressRange(from: "10.0.0.2/24")!
			interfaceConfig.addresses = [address]

			// Configure DNS.
			let dns = try DNSServer(from: "1.1.1.1")!
			interfaceConfig.dns = [dns]

			// Create peer configuration.
			// In real usage, this would be your VPN server's public key and endpoint.
			let peerPublicKey = privateKey.publicKey  // Replace with actual server key
			var peerConfig = PeerConfiguration(publicKey: peerPublicKey)

			// Configure peer endpoint.
			let endpoint = try Endpoint(from: "203.0.113.1:51820")!
			peerConfig.endpoint = endpoint

			// Configure routes (what traffic goes through the VPN).
			// This example uses full-tunnel (all traffic).
			let defaultRoute = try IPAddressRange(from: "0.0.0.0/0")!
			peerConfig.allowedIPs = [defaultRoute]

			// Create tunnel configuration.
			return try TunnelConfiguration(
				name: "Example Tunnel",
				interface: interfaceConfig,
				peers: [peerConfig]
			)!
		}
	}

#endif  // End of example code
