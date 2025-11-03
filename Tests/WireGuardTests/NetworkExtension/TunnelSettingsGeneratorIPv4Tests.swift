import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for IPv4 settings generation.
///
/// These tests verify that TunnelSettingsGenerator correctly creates IPv4 network
/// settings from WireGuard tunnel configurations. IPv4 settings include the tunnel's
/// IP address, subnet mask, and related configuration.
///
/// NetworkExtension requires specific IPv4 settings to be configured before a VPN
/// tunnel can be established. These tests ensure our generator produces valid settings.
@Suite("Tunnel settings generator IPv4 tests")
struct TunnelSettingsGeneratorIPv4Tests {

	/// Test that generator creates IPv4 settings when configuration has IPv4 addresses.
	///
	/// When a tunnel configuration contains one or more IPv4 addresses, the generator
	/// should create NEIPv4Settings with those addresses. This is the most common
	/// configuration scenario.
	@Test("Generates IPv4 settings from single IPv4 address")
	func testGeneratesIPv4SettingsFromSingleAddress() throws {
		// Create a minimal tunnel configuration with one IPv4 address.
		// This simulates a typical VPN client configuration.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add an IPv4 address in CIDR notation.
		// "10.0.0.2/24" means the interface gets IP 10.0.0.2 on a /24 subnet.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Create a peer (VPN server) with a public key.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)

		// Set the peer's endpoint (server address and port).
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Add a default route to send all IPv4 traffic through the tunnel.
		let defaultRoute = try #require(IPAddressRange(from: "0.0.0.0/0"))
		peerConfig.allowedIPs = [defaultRoute]

		// Create the complete tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Test Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Create the settings generator.
		// The tunnel remote address is the peer's endpoint IP.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)

		// Generate the NetworkExtension settings.
		let settings = try generator.generateNetworkSettings()

		// Verify IPv4 settings were created.
		#expect(settings.ipv4Settings != nil)

		// Verify the IPv4 address matches what we configured.
		#expect(settings.ipv4Settings?.addresses.first == "10.0.0.2")

		// Verify the subnet mask is correct for a /24 network.
		// A /24 CIDR means subnet mask 255.255.255.0.
		#expect(settings.ipv4Settings?.subnetMasks.first == "255.255.255.0")
	}

	/// Test that generator creates IPv4 settings with multiple addresses.
	///
	/// Some VPN configurations assign multiple IP addresses to the tunnel interface.
	/// The generator should handle this correctly and include all addresses.
	@Test("Generates IPv4 settings from multiple IPv4 addresses")
	func testGeneratesIPv4SettingsFromMultipleAddresses() throws {
		// Create configuration with multiple IPv4 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add two IPv4 addresses with different subnets.
		let ipv4Range1 = try #require(IPAddressRange(from: "10.0.0.2/24"))
		let ipv4Range2 = try #require(IPAddressRange(from: "10.1.0.2/16"))
		interfaceConfig.addresses = [ipv4Range1, ipv4Range2]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Multi-Address Tunnel",
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

		// Verify both addresses are included.
		#expect(settings.ipv4Settings?.addresses.count == 2)
		#expect(settings.ipv4Settings?.addresses.contains("10.0.0.2") == true)
		#expect(settings.ipv4Settings?.addresses.contains("10.1.0.2") == true)

		// Verify subnet masks are correct for each address.
		#expect(settings.ipv4Settings?.subnetMasks.count == 2)
		#expect(settings.ipv4Settings?.subnetMasks.contains("255.255.255.0") == true)  // /24
		#expect(settings.ipv4Settings?.subnetMasks.contains("255.255.0.0") == true)  // /16
	}

	/// Test that generator handles IPv6-only configuration.
	///
	/// When a configuration has only IPv6 addresses and no IPv4, the generator
	/// should not create IPv4 settings. This tests that the generator correctly
	/// identifies when IPv4 configuration is not present.
	@Test("Does not generate IPv4 settings for IPv6-only configuration")
	func testDoesNotGenerateIPv4SettingsForIPv6Only() throws {
		// Create configuration with only IPv6 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add only an IPv6 address (no IPv4).
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv6Range]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "IPv6-Only Tunnel",
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

		// Verify no IPv4 settings were created.
		// For an IPv6-only tunnel, ipv4Settings should be nil.
		#expect(settings.ipv4Settings == nil)
	}

	/// Test that generator handles dual-stack configuration.
	///
	/// Dual-stack means both IPv4 and IPv6 are configured. This is common in
	/// modern VPN setups. The generator should create both IPv4 and IPv6 settings.
	@Test("Generates IPv4 settings for dual-stack configuration")
	func testGeneratesIPv4SettingsForDualStack() throws {
		// Create configuration with both IPv4 and IPv6 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add both IPv4 and IPv6 addresses.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv4Range, ipv6Range]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Dual-Stack Tunnel",
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

		// Verify both IPv4 and IPv6 settings exist.
		#expect(settings.ipv4Settings != nil)
		#expect(settings.ipv6Settings != nil)

		// Verify IPv4 address is correct.
		#expect(settings.ipv4Settings?.addresses.first == "10.0.0.2")

		// Verify IPv6 address is correct.
		#expect(settings.ipv6Settings?.addresses.first == "fd00::2")
	}
}
