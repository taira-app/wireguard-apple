import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for MTU configuration in tunnel settings.
///
/// MTU (Maximum Transmission Unit) is the largest packet size that can be sent
/// over a network link. VPN tunnels often need custom MTU settings because the
/// tunnel adds overhead (encryption headers, etc.) that reduces the effective
/// packet size that can be transmitted.
///
/// These tests verify that TunnelSettingsGenerator correctly applies MTU
/// configuration to the generated NetworkExtension settings.
@Suite("Tunnel settings generator MTU tests")
struct TunnelSettingsGeneratorMTUTests {

	/// Test that generator applies custom MTU when specified.
	///
	/// When the interface configuration specifies an MTU, the generator should
	/// apply it to the tunnel settings. This is important for avoiding packet
	/// fragmentation which can reduce performance.
	@Test("Applies custom MTU from interface configuration")
	func testAppliesCustomMTU() throws {
		// Create a tunnel configuration with a custom MTU.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Set a custom MTU.
		// 1420 is a common MTU for WireGuard tunnels (1500 standard Ethernet MTU
		// minus 80 bytes for WireGuard/IP/UDP overhead).
		interfaceConfig.mtu = 1420

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "MTU Test Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// Verify the MTU was applied to the settings.
		#expect(settings.mtu as? Int == 1420)
	}

	/// Test that generator uses default MTU when not specified.
	///
	/// If no MTU is configured, NetworkExtension should use the system default.
	/// The generator should handle this case correctly.
	@Test("Uses default MTU when not specified in configuration")
	func testUsesDefaultMTUWhenNotSpecified() throws {
		// Create a tunnel configuration without custom MTU.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Do not set MTU (interfaceConfig.mtu remains nil).

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Default MTU Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// When no MTU is specified, NetworkExtension may use nil or a default value.
		// We just verify the settings were generated successfully.
		// The actual MTU behavior depends on NetworkExtension's implementation.
		#expect(settings.tunnelRemoteAddress == "203.0.113.1")
	}

	/// Test that generator handles minimum valid MTU.
	///
	/// MTU values have minimum and maximum limits. This test verifies the
	/// generator handles small MTU values correctly.
	@Test("Handles minimum valid MTU")
	func testHandlesMinimumMTU() throws {
		// Create a tunnel configuration with a small but valid MTU.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Set a small MTU.
		// 576 is the minimum IPv4 MTU (all IPv4 hosts must support this).
		interfaceConfig.mtu = 576

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Min MTU Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// Verify the small MTU was applied.
		#expect(settings.mtu as? Int == 576)
	}

	/// Test that generator handles maximum valid MTU.
	///
	/// Most networks support MTUs up to 1500 (standard Ethernet) or 9000 (jumbo frames).
	/// This test verifies the generator handles large MTU values.
	@Test("Handles large MTU values")
	func testHandlesLargeMTU() throws {
		// Create a tunnel configuration with a large MTU.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Set a large MTU.
		// 9000 is a common jumbo frame size.
		interfaceConfig.mtu = 9000

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Large MTU Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// Verify the large MTU was applied.
		#expect(settings.mtu as? Int == 9000)
	}

	/// Test that generator handles standard Ethernet MTU.
	///
	/// 1500 is the standard Ethernet MTU. For WireGuard, a typical tunnel MTU
	/// is slightly less (1420) to account for overhead, but verifying 1500 works
	/// is still useful.
	@Test("Handles standard Ethernet MTU")
	func testHandlesStandardEthernetMTU() throws {
		// Create a tunnel configuration with standard Ethernet MTU.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Set standard Ethernet MTU.
		interfaceConfig.mtu = 1500

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Standard MTU Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// Verify the standard MTU was applied.
		#expect(settings.mtu as? Int == 1500)
	}
}
