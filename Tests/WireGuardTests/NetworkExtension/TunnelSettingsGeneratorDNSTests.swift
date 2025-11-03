import NetworkExtension
import Testing

@testable import WireGuard

/// Tests for DNS settings generation.
///
/// These tests verify that TunnelSettingsGenerator correctly creates DNS settings
/// from WireGuard tunnel configurations. DNS configuration is important for VPNs
/// because it controls which DNS servers are used while the tunnel is active.
///
/// Many VPNs use custom DNS servers to provide privacy, security, or access to
/// internal resources. The generator must correctly configure these DNS settings
/// in NetworkExtension.
@Suite("Tunnel settings generator DNS tests")
struct TunnelSettingsGeneratorDNSTests {

	/// Test that generator creates DNS settings when DNS servers are configured.
	///
	/// When the interface configuration includes DNS servers, the generator should
	/// create NEDNSSettings with those servers.
	@Test("Generates DNS settings from single DNS server")
	func testGeneratesDNSSettingsFromSingleServer() throws {
		// Create a tunnel configuration with a DNS server.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Add a DNS server.
		// Using Cloudflare's public DNS server as an example.
		let dnsServer = try #require(DNSServer(from: "1.1.1.1"))
		interfaceConfig.dns = [dnsServer]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "DNS Test Tunnel",
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

		// Verify DNS settings were created.
		#expect(settings.dnsSettings != nil)

		// Verify the DNS server matches what we configured.
		#expect(settings.dnsSettings?.servers.first == "1.1.1.1")
	}

	/// Test that generator creates DNS settings with multiple DNS servers.
	///
	/// Many VPN configurations specify multiple DNS servers for redundancy.
	/// If the first server is unavailable, the system will try the next one.
	@Test("Generates DNS settings from multiple DNS servers")
	func testGeneratesDNSSettingsFromMultipleServers() throws {
		// Create a tunnel configuration with multiple DNS servers.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Add multiple DNS servers.
		// Using Cloudflare and Google public DNS as examples.
		let dnsServer1 = try #require(DNSServer(from: "1.1.1.1"))  // Cloudflare
		let dnsServer2 = try #require(DNSServer(from: "8.8.8.8"))  // Google
		interfaceConfig.dns = [dnsServer1, dnsServer2]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Multi-DNS Tunnel",
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

		// Verify both DNS servers are included.
		#expect(settings.dnsSettings?.servers.count == 2)
		#expect(settings.dnsSettings?.servers.contains("1.1.1.1") == true)
		#expect(settings.dnsSettings?.servers.contains("8.8.8.8") == true)
	}

	/// Test that generator handles IPv6 DNS servers.
	///
	/// DNS servers can be IPv6 addresses. The generator should handle these
	/// correctly alongside or instead of IPv4 DNS servers.
	@Test("Generates DNS settings with IPv6 DNS server")
	func testGeneratesDNSSettingsWithIPv6Server() throws {
		// Create a tunnel configuration with an IPv6 DNS server.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add tunnel addresses (dual-stack).
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		let ipv6Range = try #require(IPAddressRange(from: "fd00::2/64"))
		interfaceConfig.addresses = [ipv4Range, ipv6Range]

		// Add an IPv6 DNS server.
		// Using Cloudflare's IPv6 DNS server.
		let dnsServer = try #require(DNSServer(from: "2606:4700:4700::1111"))
		interfaceConfig.dns = [dnsServer]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "IPv6 DNS Tunnel",
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

		// Verify DNS settings include the IPv6 server.
		#expect(settings.dnsSettings?.servers.first == "2606:4700:4700::1111")
	}

	/// Test that generator creates DNS settings with search domains.
	///
	/// DNS search domains are used to automatically append domain suffixes
	/// to short hostnames. For example, with search domain "example.com",
	/// looking up "server" would try "server.example.com".
	@Test("Generates DNS settings with search domains")
	func testGeneratesDNSSettingsWithSearchDomains() throws {
		// Create a tunnel configuration with DNS search domains.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Add a DNS server.
		let dnsServer = try #require(DNSServer(from: "10.0.0.1"))
		interfaceConfig.dns = [dnsServer]

		// Add DNS search domains.
		// These are commonly used in corporate VPNs to access internal resources.
		interfaceConfig.dnsSearch = ["internal.example.com", "vpn.example.com"]

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "Search Domains Tunnel",
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

		// Verify DNS search domains are included.
		#expect(settings.dnsSettings?.searchDomains?.count == 2)
		#expect(settings.dnsSettings?.searchDomains?.contains("internal.example.com") == true)
		#expect(settings.dnsSettings?.searchDomains?.contains("vpn.example.com") == true)
	}

	/// Test that generator handles configuration with no DNS settings.
	///
	/// Not all VPN configurations specify custom DNS servers. When no DNS
	/// configuration is provided, the generator should either omit DNS settings
	/// or create empty DNS settings (depending on NetworkExtension requirements).
	@Test("Handles configuration with no DNS servers")
	func testHandlesConfigurationWithNoDNS() throws {
		// Create a tunnel configuration without DNS servers.
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)

		// Add a tunnel IP address.
		let ipv4Range = try #require(IPAddressRange(from: "10.0.0.2/24"))
		interfaceConfig.addresses = [ipv4Range]

		// Do not add any DNS servers (interfaceConfig.dns is empty by default).

		// Create peer configuration.
		let peerPublicKey = privateKey.publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		let endpoint = try #require(Endpoint(from: "203.0.113.1:51820"))
		peerConfig.endpoint = endpoint

		// Create tunnel configuration.
		let config = try TunnelConfiguration(
			name: "No DNS Tunnel",
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

		// Verify either no DNS settings or empty DNS settings.
		// NetworkExtension may require DNS settings to exist even if empty.
		if let dnsSettings = settings.dnsSettings {
			#expect(dnsSettings.servers.isEmpty)
		}
	}
}
