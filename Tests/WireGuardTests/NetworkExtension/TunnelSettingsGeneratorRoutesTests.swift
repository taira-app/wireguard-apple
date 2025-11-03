import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for route generation from peer allowed IPs.
///
/// These tests verify that TunnelSettingsGenerator correctly converts peer allowedIPs
/// into NetworkExtension routes. Routes determine which network traffic is sent through
/// the VPN tunnel versus the regular internet connection.
///
/// WireGuard uses the "allowedIPs" field on each peer to specify which destination IPs
/// should be routed through that peer. The generator must convert these into NEIPv4Route
/// and NEIPv6Route objects that NetworkExtension can use.
@Suite("Tunnel settings generator routes tests")
struct TunnelSettingsGeneratorRoutesTests {

	/// Test that generator creates routes from peer allowed IPs.
	///
	/// When a peer specifies allowed IPs, those IP ranges should be added as routes
	/// in the tunnel settings. This is how VPNs implement split-tunneling: only certain
	/// traffic goes through the VPN.
	@Test("Generates IPv4 routes from peer allowed IPs")
	func testGeneratesIPv4RoutesFromAllowedIPs() throws {
		// Create a tunnel configuration with specific allowed IPs.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Create peer with specific allowed IPs (split-tunnel configuration).
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Allow two specific IP ranges through the tunnel.
		// This creates a split-tunnel: only these ranges use the VPN.
		let allowedIP1 = try #require(IPAddressRange(from: "192.168.1.0/24"))
		let allowedIP2 = try #require(IPAddressRange(from: "10.10.0.0/16"))
		peerConfig.allowedIPs = [allowedIP1, allowedIP2]

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Split-Tunnel",
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

		// Verify routes were created for the allowed IPs.
		let routes = settings.ipv4Settings?.includedRoutes ?? []
		#expect(routes.count == 2)

		// Check that routes match the allowed IPs.
		// Routes are NEIPv4Route objects with destinationAddress and subnetMask.
		let routeAddresses = routes.map { $0.destinationAddress }
		#expect(routeAddresses.contains("192.168.1.0") == true)
		#expect(routeAddresses.contains("10.10.0.0") == true)
	}

	/// Test that generator creates a default route for full-tunnel configuration.
	///
	/// A default route (0.0.0.0/0 for IPv4 or ::/0 for IPv6) means all traffic
	/// goes through the VPN. This is called full-tunneling and is common for
	/// privacy-focused VPNs.
	@Test("Generates default IPv4 route for full-tunnel configuration")
	func testGeneratesDefaultIPv4Route() throws {
		// Create a full-tunnel configuration.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Create peer with default route (all IPv4 traffic).
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// 0.0.0.0/0 means "all IPv4 addresses" - a default route.
		let defaultRoute = try #require(IPAddressRange(from: "0.0.0.0/0"))
		peerConfig.allowedIPs = [defaultRoute]

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Full-Tunnel",
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

		// Verify a default route was created.
		let routes = settings.ipv4Settings?.includedRoutes ?? []
		#expect(routes.count == 1)

		// Verify it's the default route (0.0.0.0/0).
		#expect(routes.first?.destinationAddress == "0.0.0.0")
		#expect(routes.first?.destinationSubnetMask == "0.0.0.0")
	}

	/// Test that generator creates IPv6 routes from peer allowed IPs.
	///
	/// Similar to IPv4 routes, but for IPv6 address ranges. IPv6 routes use
	/// network prefix lengths instead of subnet masks.
	@Test("Generates IPv6 routes from peer allowed IPs")
	func testGeneratesIPv6RoutesFromAllowedIPs() throws {
		// Create a tunnel configuration with IPv6 allowed IPs.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add an IPv6 tunnel address.
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv6Range]

		// Create peer with specific IPv6 allowed IPs.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Allow specific IPv6 ranges.
		let allowedIP1 = try #require(IPAddressRange(from: "fd01::/64"))
		let allowedIP2 = try #require(IPAddressRange(from: "fd02::/48"))
		peerConfig.allowedIPs = [allowedIP1, allowedIP2]

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "IPv6 Routes Tunnel",
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

		// Verify IPv6 routes were created.
		let routes = settings.ipv6Settings?.includedRoutes ?? []
		#expect(routes.count == 2)

		// Check that routes match the allowed IPs.
		let routeAddresses = routes.map { $0.destinationAddress }
		#expect(routeAddresses.contains("fd01::") == true)
		#expect(routeAddresses.contains("fd02::") == true)
	}

	/// Test that generator creates default IPv6 route for full-tunnel.
	///
	/// The IPv6 equivalent of 0.0.0.0/0 is ::/0, which means all IPv6 traffic.
	@Test("Generates default IPv6 route for full-tunnel configuration")
	func testGeneratesDefaultIPv6Route() throws {
		// Create a full-tunnel IPv6 configuration.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add an IPv6 tunnel address.
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv6Range]

		// Create peer with default IPv6 route.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// ::/0 means "all IPv6 addresses" - a default route.
		let defaultRoute = try #require(IPAddressRange(from: "::/0"))
		peerConfig.allowedIPs = [defaultRoute]

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Full-Tunnel IPv6",
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

		// Verify a default IPv6 route was created.
		let routes = settings.ipv6Settings?.includedRoutes ?? []
		#expect(routes.count == 1)

		// Verify it's the default route (::/0).
		#expect(routes.first?.destinationAddress == "::")
		// IPv6 routes use network prefix length, not subnet mask.
		#expect(routes.first?.destinationNetworkPrefixLength as? Int == 0)
	}

	/// Test that generator handles dual-stack routes.
	///
	/// A dual-stack configuration can have both IPv4 and IPv6 routes.
	/// The generator should create both types of routes correctly.
	@Test("Generates both IPv4 and IPv6 routes for dual-stack configuration")
	func testGeneratesDualStackRoutes() throws {
		// Create a dual-stack configuration with both IPv4 and IPv6 routes.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add both IPv4 and IPv6 addresses.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv4Range, ipv6Range]

		// Create peer with both IPv4 and IPv6 allowed IPs.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Add both IPv4 and IPv6 allowed IPs.
		let ipv4AllowedIP = try #require(IPAddressRange(from: "192.168.0.0/16"))
		let ipv6AllowedIP = try #require(IPAddressRange(from: "fd01::/64"))
		peerConfig.allowedIPs = [ipv4AllowedIP, ipv6AllowedIP]

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Dual-Stack Routes",
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

		// Verify both IPv4 and IPv6 routes were created.
		let ipv4Routes = settings.ipv4Settings?.includedRoutes ?? []
		let ipv6Routes = settings.ipv6Settings?.includedRoutes ?? []

		#expect(ipv4Routes.count == 1)
		#expect(ipv6Routes.count == 1)

		#expect(ipv4Routes.first?.destinationAddress == "192.168.0.0")
		#expect(ipv6Routes.first?.destinationAddress == "fd01::")
	}

	/// Test that generator aggregates routes from multiple peers.
	///
	/// A tunnel can have multiple peers, and each peer can have different allowed IPs.
	/// The generator should combine all allowed IPs into a single set of routes.
	@Test("Aggregates routes from multiple peers")
	func testAggregatesRoutesFromMultiplePeers() throws {
		// Create a configuration with multiple peers.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Create first peer with its own allowed IPs.
		let peer1PublicKey = PrivateKey().publicKey
		var peer1Config = PeerConfiguration(publicKey: peer1PublicKey)
		let endpoint1 = try #require(Endpoint(from: "203.0.113.1:51820"))
		peer1Config.endpoint = endpoint1
		let peer1AllowedIP = try #require(IPAddressRange(from: "192.168.1.0/24"))
		peer1Config.allowedIPs = [peer1AllowedIP]

		// Create second peer with different allowed IPs.
		let peer2PublicKey = PrivateKey().publicKey
		var peer2Config = PeerConfiguration(publicKey: peer2PublicKey)
		let endpoint2 = try #require(Endpoint(from: "203.0.113.2:51820"))
		peer2Config.endpoint = endpoint2
		let peer2AllowedIP = try #require(IPAddressRange(from: "10.10.0.0/16"))
		peer2Config.allowedIPs = [peer2AllowedIP]

		// Create tunnel configuration with both peers.
		let config = try TunnelConfiguration(
			name: "Multi-Peer Tunnel",
			interface: interfaceConfig,
			peers: [peer1Config, peer2Config]
		)
		let tunnelConfig = try #require(config)

		// Generate settings.
		let generator = TunnelSettingsGenerator(
			configuration: tunnelConfig,
			tunnelRemoteAddress: "203.0.113.1"
		)
		let settings = try generator.generateNetworkSettings()

		// Verify routes from both peers are included.
		let routes = settings.ipv4Settings?.includedRoutes ?? []
		#expect(routes.count == 2)

		let routeAddresses = routes.map { $0.destinationAddress }
		#expect(routeAddresses.contains("192.168.1.0") == true)
		#expect(routeAddresses.contains("10.10.0.0") == true)
	}
}
