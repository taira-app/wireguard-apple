// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

@testable import WireGuard

/// Shared test helpers for WireGuard tunnel tests.
///
/// This enum provides common test utilities used across multiple test files
/// to avoid code duplication.
enum TestHelpers {
	/// Creates a test configuration with minimal valid settings.
	///
	/// This helper creates a configuration suitable for testing that includes
	/// an interface with a private key and one peer with a public key. The
	/// configuration is valid but uses generated keys rather than real ones.
	///
	/// - Returns: A valid tunnel configuration for testing
	static func createTestConfiguration() throws -> TunnelConfiguration {
		// Create interface configuration
		let privateKey = PrivateKey()
		var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)
		interfaceConfig.addresses = [
			IPAddressRange(from: "10.0.0.2/24")!
		]

		// Create peer configuration
		let peerPublicKey = PrivateKey().publicKey
		var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
		peerConfig.allowedIPs = [
			IPAddressRange(from: "0.0.0.0/0")!
		]

		// Create tunnel configuration
		return try TunnelConfiguration(
			name: "Test Tunnel",
			interface: interfaceConfig,
			peers: [peerConfig]
		)
	}
}
