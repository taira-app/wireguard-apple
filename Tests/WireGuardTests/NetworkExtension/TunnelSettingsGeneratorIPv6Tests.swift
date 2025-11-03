import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for IPv6 settings generation.
///
/// These tests verify that TunnelSettingsGenerator correctly creates IPv6 network
/// settings from WireGuard tunnel configurations. IPv6 is increasingly important
/// as IPv4 addresses become scarce, and many VPN configurations now use IPv6.
@Suite("Tunnel settings generator IPv6 tests")
struct TunnelSettingsGeneratorIPv6Tests {

	/// Test that generator creates IPv6 settings when configuration has IPv6 addresses.
	///
	/// When a tunnel configuration contains one or more IPv6 addresses, the generator
	/// should create NEIPv6Settings with those addresses and network prefix lengths.
	@Test("Generates IPv6 settings from single IPv6 address")
	func testGeneratesIPv6SettingsFromSingleAddress() throws {
		// Create a minimal tunnel configuration with one IPv6 address.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add an IPv6 address in CIDR notation.
		// "fd00::2/64" means the interface gets IP fd00::2 on a /64 subnet.
		// fd00::/8 is the unique local address (ULA) range, similar to private IPv4.
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv6Range]

		// Create a peer (VPN server) with a public key.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)

		// Set the peer's endpoint.
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Add a default route for all IPv6 traffic.
		let defaultRoute = try #require(IPAddressRange(from: "::/0"))
		peerConfig.allowedIPs = [defaultRoute]

		// Create the complete tunnel configuration.
		let config = try TunnelConfiguration(
			name: "IPv6 Test Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
		let tunnelConfig = try #require(config)

		// Create the settings generator.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)

		// Generate the NetworkExtension settings.
		let settings = try generator.generateNetworkSettings()

		// Verify IPv6 settings were created.
		#expect(settings.ipv6Settings != nil)

		// Verify the IPv6 address matches what we configured.
		#expect(settings.ipv6Settings?.addresses.first == "fd00::2")

		// Verify the network prefix length is correct for a /64 network.
		#expect(settings.ipv6Settings?.networkPrefixLengths.first as? Int == 64)
	}

	/// Test that generator creates IPv6 settings with multiple addresses.
	///
	/// Some VPN configurations use multiple IPv6 addresses on the tunnel interface.
	/// The generator should include all of them in the settings.
	@Test("Generates IPv6 settings from multiple IPv6 addresses")
	func testGeneratesIPv6SettingsFromMultipleAddresses() throws {
		// Create configuration with multiple IPv6 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add two IPv6 addresses with different prefix lengths.
		let ipv6Range1 = try #require(IPAddressRange(from: "fd00::2/64"))
		let ipv6Range2 = try #require(IPAddressRange(from: "fd01::3/48"))
		interfaceConfig.addresses = [ipv6Range1, ipv6Range2]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Multi-IPv6 Tunnel",
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

		// Verify both IPv6 addresses are included.
		#expect(settings.ipv6Settings?.addresses.count == 2)
		#expect(settings.ipv6Settings?.addresses.contains("fd00::2") == true)
		#expect(settings.ipv6Settings?.addresses.contains("fd01::3") == true)

		// Verify network prefix lengths are correct for each address.
		#expect(settings.ipv6Settings?.networkPrefixLengths.count == 2)
		// NetworkExtension uses NSNumber for prefix lengths, so we cast to Int for comparison.
		let prefixLengths = settings.ipv6Settings?.networkPrefixLengths.compactMap { $0 as? Int }
		#expect(prefixLengths?.contains(64) == true)  // /64
		#expect(prefixLengths?.contains(48) == true)  // /48
	}

	/// Test that generator handles IPv4-only configuration.
	///
	/// When a configuration has only IPv4 addresses and no IPv6, the generator
	/// should not create IPv6 settings.
	@Test("Does not generate IPv6 settings for IPv4-only configuration")
	func testDoesNotGenerateIPv6SettingsForIPv4Only() throws {
		// Create configuration with only IPv4 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add only an IPv4 address (no IPv6).
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "IPv4-Only Tunnel",
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

		// Verify no IPv6 settings were created.
		#expect(settings.ipv6Settings == nil)
	}

	/// Test that generator handles dual-stack configuration.
	///
	/// For dual-stack (both IPv4 and IPv6), verify that IPv6 settings are
	/// created alongside IPv4 settings.
	@Test("Generates IPv6 settings for dual-stack configuration")
	func testGeneratesIPv6SettingsForDualStack() throws {
		// Create configuration with both IPv4 and IPv6 addresses.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add both address types.
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

		// Verify IPv6 address is correct.
		#expect(settings.ipv6Settings?.addresses.first == "fd00::2")

		// Verify IPv4 address is correct.
		#expect(settings.ipv4Settings?.addresses.first == "10.0.0.2")
	}
}
