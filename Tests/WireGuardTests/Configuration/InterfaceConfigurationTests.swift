// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Network
import Testing

@testable import WireGuard

/// Tests for the InterfaceConfiguration struct.
///
/// These tests verify interface configuration creation, validation, and modification.
/// They ensure that interface configurations meet WireGuard protocol requirements
/// and properly validate all fields.
@Suite("Interface configuration tests")
struct InterfaceConfigurationTests {

	// MARK: - Test fixtures

	/// Creates a valid private key for testing.
	func makePrivateKey() -> PrivateKey {
		return PrivateKey()
	}

	/// Creates a valid IPv4 address range for testing.
	func makeIPv4AddressRange() throws -> IPAddressRange {
		return try #require(IPAddressRange(from: "10.0.0.2/24"))
	}

	/// Creates a valid IPv6 address range for testing.
	func makeIPv6AddressRange() throws -> IPAddressRange {
		return try #require(IPAddressRange(from: "fd00::2/64"))
	}

	/// Creates a valid DNS server for testing.
	func makeDNSServer() throws -> DNSServer {
		return try #require(DNSServer(from: "1.1.1.1"))
	}

	// MARK: - Initialization tests

	/// Test that InterfaceConfiguration can be initialized with just a private key.
	///
	/// The minimum valid configuration requires only a private key. Other fields
	/// should have sensible defaults.
	@Test("Interface configuration can be initialized with private key")
	func initializeWithPrivateKey() throws {
		// Given: a private key
		let privateKey = makePrivateKey()

		// When: creating an interface configuration
		let configuration = InterfaceConfiguration(privateKey: privateKey)

		// Then: configuration is created with the private key
		#expect(configuration.privateKey == privateKey)
	}

	/// Test that newly initialized configuration has empty addresses array.
	///
	/// By default, the addresses array should be empty and ready for population.
	@Test("New interface configuration has empty addresses")
	func newConfigurationHasEmptyAddresses() throws {
		// Given: a new interface configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: addresses array is empty
		#expect(configuration.addresses.isEmpty)
	}

	/// Test that newly initialized configuration has empty DNS array.
	///
	/// By default, the DNS servers array should be empty.
	@Test("New interface configuration has empty DNS servers")
	func newConfigurationHasEmptyDNS() throws {
		// Given: a new interface configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: DNS array is empty
		#expect(configuration.dns.isEmpty)
	}

	/// Test that newly initialized configuration has empty DNS search domains.
	///
	/// By default, the DNS search domains array should be empty.
	@Test("New interface configuration has empty DNS search domains")
	func newConfigurationHasEmptyDNSSearch() throws {
		// Given: a new interface configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: DNS search domains array is empty
		#expect(configuration.dnsSearch.isEmpty)
	}

	/// Test that newly initialized configuration has no listen port.
	///
	/// Listen port is optional and should be nil by default (client configuration).
	@Test("New interface configuration has no listen port")
	func newConfigurationHasNoListenPort() throws {
		// Given: a new interface configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: listen port is nil
		#expect(configuration.listenPort == nil)
	}

	/// Test that newly initialized configuration has no MTU.
	///
	/// MTU is optional and should be nil by default (system will choose MTU).
	@Test("New interface configuration has no MTU")
	func newConfigurationHasNoMTU() throws {
		// Given: a new interface configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: MTU is nil
		#expect(configuration.mtu == nil)
	}

	// MARK: - Address configuration tests

	/// Test that addresses can be added to the configuration.
	///
	/// Interface configurations need at least one address for routing.
	@Test("Addresses can be added to configuration")
	func addAddresses() throws {
		// Given: a configuration
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: adding addresses
		let ipv4 = try makeIPv4AddressRange()
		let ipv6 = try makeIPv6AddressRange()
		configuration.addresses = [ipv4, ipv6]

		// Then: addresses are stored
		#expect(configuration.addresses.count == 2)
		#expect(configuration.addresses.contains(ipv4))
		#expect(configuration.addresses.contains(ipv6))
	}

	/// Test that configuration can have IPv4-only addresses.
	///
	/// Single-stack IPv4 configurations are valid.
	@Test("Configuration can be IPv4-only")
	func ipv4OnlyConfiguration() throws {
		// Given: a configuration with IPv4 address
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())
		configuration.addresses = [try makeIPv4AddressRange()]

		// Then: configuration has one IPv4 address
		#expect(configuration.addresses.count == 1)
	}

	/// Test that configuration can have IPv6-only addresses.
	///
	/// Single-stack IPv6 configurations are valid.
	@Test("Configuration can be IPv6-only")
	func ipv6OnlyConfiguration() throws {
		// Given: a configuration with IPv6 address
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())
		configuration.addresses = [try makeIPv6AddressRange()]

		// Then: configuration has one IPv6 address
		#expect(configuration.addresses.count == 1)
	}

	/// Test that configuration can be dual-stack.
	///
	/// Dual-stack (IPv4 + IPv6) configurations are common and fully supported.
	@Test("Configuration can be dual-stack")
	func dualStackConfiguration() throws {
		// Given: a configuration with both IPv4 and IPv6
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())
		configuration.addresses = [
			try makeIPv4AddressRange(),
			try makeIPv6AddressRange()
		]

		// Then: configuration has both address types
		#expect(configuration.addresses.count == 2)
	}

	// MARK: - DNS configuration tests

	/// Test that DNS servers can be added to the configuration.
	///
	/// DNS configuration allows the tunnel to handle DNS queries.
	@Test("DNS servers can be added to configuration")
	func addDNSServers() throws {
		// Given: a configuration
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: adding DNS servers
		let dns1 = try makeDNSServer()
		let dns2 = try #require(DNSServer(from: "8.8.8.8"))
		configuration.dns = [dns1, dns2]

		// Then: DNS servers are stored
		#expect(configuration.dns.count == 2)
		#expect(configuration.dns.contains(dns1))
		#expect(configuration.dns.contains(dns2))
	}

	/// Test that DNS search domains can be added to the configuration.
	///
	/// DNS search domains allow short hostname resolution.
	@Test("DNS search domains can be added to configuration")
	func addDNSSearchDomains() throws {
		// Given: a configuration
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: adding DNS search domains
		configuration.dnsSearch = ["example.com", "internal.local"]

		// Then: DNS search domains are stored
		#expect(configuration.dnsSearch.count == 2)
		#expect(configuration.dnsSearch.contains("example.com"))
		#expect(configuration.dnsSearch.contains("internal.local"))
	}

	// MARK: - Optional field tests

	/// Test that listen port can be set.
	///
	/// Listen port is used for server-side configurations to specify
	/// which UDP port to listen on.
	@Test("Listen port can be set")
	func setListenPort() throws {
		// Given: a configuration
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: setting listen port
		configuration.listenPort = 51820

		// Then: listen port is stored
		#expect(configuration.listenPort == 51820)
	}

	/// Test that listen port can be cleared.
	///
	/// Clearing the listen port reverts to client mode (no listening).
	@Test("Listen port can be cleared")
	func clearListenPort() throws {
		// Given: a configuration with listen port
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())
		configuration.listenPort = 51820

		// When: clearing listen port
		configuration.listenPort = nil

		// Then: listen port is nil
		#expect(configuration.listenPort == nil)
	}

	/// Test that MTU can be set to valid values.
	///
	/// MTU should accept values in the valid range (1280-65535).
	@Test("MTU can be set to valid value")
	func setValidMTU() throws {
		// Given: a configuration
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: setting MTU to valid value
		configuration.mtu = 1420

		// Then: MTU is stored
		#expect(configuration.mtu == 1420)
	}

	/// Test that MTU can be cleared.
	///
	/// Clearing MTU allows the system to choose the default MTU.
	@Test("MTU can be cleared")
	func clearMTU() throws {
		// Given: a configuration with MTU
		var configuration = InterfaceConfiguration(privateKey: makePrivateKey())
		configuration.mtu = 1420

		// When: clearing MTU
		configuration.mtu = nil

		// Then: MTU is nil
		#expect(configuration.mtu == nil)
	}

	// MARK: - Equatable tests

	/// Test that two configurations with same values are equal.
	///
	/// Equatable should compare all fields for equality.
	@Test("Configurations with same values are equal")
	func configurationsWithSameValuesAreEqual() throws {
		// Given: two configurations with same data
		let privateKey = makePrivateKey()
		let address = try makeIPv4AddressRange()
		let dns = try makeDNSServer()

		var config1 = InterfaceConfiguration(privateKey: privateKey)
		config1.addresses = [address]
		config1.dns = [dns]
		config1.listenPort = 51820
		config1.mtu = 1420

		var config2 = InterfaceConfiguration(privateKey: privateKey)
		config2.addresses = [address]
		config2.dns = [dns]
		config2.listenPort = 51820
		config2.mtu = 1420

		// Then: configurations are equal
		#expect(config1 == config2)
	}

	/// Test that configurations with different private keys are not equal.
	///
	/// Different private keys mean different interface identities.
	@Test("Configurations with different private keys are not equal")
	func configurationsWithDifferentPrivateKeysAreNotEqual() throws {
		// Given: two configurations with different private keys
		let config1 = InterfaceConfiguration(privateKey: makePrivateKey())
		let config2 = InterfaceConfiguration(privateKey: makePrivateKey())

		// Then: configurations are not equal
		#expect(config1 != config2)
	}

	/// Test that configurations with different addresses are not equal.
	///
	/// Different address assignments mean different configurations.
	@Test("Configurations with different addresses are not equal")
	func configurationsWithDifferentAddressesAreNotEqual() throws {
		// Given: two configurations with different addresses
		let privateKey = makePrivateKey()

		var config1 = InterfaceConfiguration(privateKey: privateKey)
		config1.addresses = [try makeIPv4AddressRange()]

		var config2 = InterfaceConfiguration(privateKey: privateKey)
		config2.addresses = [try makeIPv6AddressRange()]

		// Then: configurations are not equal
		#expect(config1 != config2)
	}

	/// Test that configurations with different listen ports are not equal.
	///
	/// Different listen ports mean different server configurations.
	@Test("Configurations with different listen ports are not equal")
	func configurationsWithDifferentListenPortsAreNotEqual() throws {
		// Given: two configurations with different listen ports
		let privateKey = makePrivateKey()

		var config1 = InterfaceConfiguration(privateKey: privateKey)
		config1.listenPort = 51820

		var config2 = InterfaceConfiguration(privateKey: privateKey)
		config2.listenPort = 51821

		// Then: configurations are not equal
		#expect(config1 != config2)
	}

	// MARK: - Sendable conformance test

	/// Test that InterfaceConfiguration conforms to Sendable.
	///
	/// Sendable conformance is required for Swift 6 concurrency.
	@Test("InterfaceConfiguration conforms to Sendable")
	func conformsToSendable() throws {
		// Given: a configuration
		let configuration = InterfaceConfiguration(privateKey: makePrivateKey())

		// When: passing to an async context
		Task {
			// Then: configuration can be sent across concurrency boundaries
			_ = configuration
		}
	}
}
