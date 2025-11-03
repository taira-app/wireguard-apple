// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation
import Testing

@testable import WireGuard

/// Tests for the ConfigurationError enumeration.
///
/// These tests verify that ConfigurationError provides appropriate error
/// descriptions, failure reasons, and recovery suggestions for each error case.
/// They ensure the error messages are user-friendly and technically accurate.
@Suite("Configuration error tests")
struct ConfigurationErrorTests {

	// MARK: - Error description tests

	/// Test that noPeers error provides a clear description.
	///
	/// The error description should concisely explain that at least one peer
	/// is required in the configuration.
	@Test("No peers error has clear description")
	func noPeersErrorDescription() {
		// Given: a noPeers error
		let error = ConfigurationError.noPeers

		// When: getting the error description
		let description = error.errorDescription

		// Then: description explains the issue clearly
		#expect(description != nil)
		#expect(description?.contains("at least one peer") == true)
	}

	/// Test that duplicatePeerPublicKey error includes the key in description.
	///
	/// The error description should identify which specific public key is
	/// duplicated to help users locate the problem.
	@Test("Duplicate peer public key error includes key in description")
	func duplicatePeerPublicKeyErrorDescription() {
		// Given: a duplicate key error with a specific public key
		let testKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
		let error = ConfigurationError.duplicatePeerPublicKey(publicKey: testKey)

		// When: getting the error description
		let description = error.errorDescription

		// Then: description includes the duplicate key
		#expect(description != nil)
		#expect(description?.contains(testKey) == true)
		#expect(description?.lowercased().contains("duplicate") == true)
	}

	/// Test that noAddresses error provides a clear description.
	///
	/// The error description should explain that the interface requires
	/// at least one IP address assignment.
	@Test("No addresses error has clear description")
	func noAddressesErrorDescription() {
		// Given: a noAddresses error
		let error = ConfigurationError.noAddresses

		// When: getting the error description
		let description = error.errorDescription

		// Then: description explains the requirement
		#expect(description != nil)
		#expect(description?.contains("at least one address") == true)
	}

	/// Test that invalidMTU error includes the MTU value in description.
	///
	/// The error description should show which MTU value was invalid to
	/// help users understand what went wrong.
	@Test("Invalid MTU error includes MTU value in description")
	func invalidMTUErrorDescription() {
		// Given: an invalid MTU error with a specific value
		let testMTU: UInt16 = 500
		let error = ConfigurationError.invalidMTU(mtu: testMTU)

		// When: getting the error description
		let description = error.errorDescription

		// Then: description includes the invalid MTU value
		#expect(description != nil)
		#expect(description?.contains("\(testMTU)") == true)
		#expect(description?.lowercased().contains("mtu") == true)
	}

	/// Test that invalidKeepalive error includes the interval in description.
	///
	/// The error description should show which keepalive interval was invalid
	/// to help users provide the correct value.
	@Test("Invalid keepalive error includes interval in description")
	func invalidKeepaliveErrorDescription() {
		// Given: an invalid keepalive error with a specific interval
		let testInterval: UInt16 = 60000
		let error = ConfigurationError.invalidKeepalive(interval: testInterval)

		// When: getting the error description
		let description = error.errorDescription

		// Then: description includes the invalid interval
		#expect(description != nil)
		#expect(description?.contains("\(testInterval)") == true)
		#expect(description?.lowercased().contains("keepalive") == true)
	}

	// MARK: - Failure reason tests

	/// Test that noPeers error provides a technical failure reason.
	///
	/// The failure reason should explain why WireGuard requires at least
	/// one peer from a protocol perspective.
	@Test("No peers error has technical failure reason")
	func noPeersFailureReason() {
		// Given: a noPeers error
		let error = ConfigurationError.noPeers

		// When: getting the failure reason
		let reason = error.failureReason

		// Then: reason explains the technical requirement
		#expect(reason != nil)
		#expect(reason?.contains("WireGuard") == true)
		#expect(reason?.lowercased().contains("peer") == true)
	}

	/// Test that duplicatePeerPublicKey error explains why duplicates are invalid.
	///
	/// The failure reason should explain that duplicate keys create routing
	/// ambiguity and violate WireGuard's security model.
	@Test("Duplicate peer public key error explains why duplicates are invalid")
	func duplicatePeerPublicKeyFailureReason() {
		// Given: a duplicate key error
		let testKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
		let error = ConfigurationError.duplicatePeerPublicKey(publicKey: testKey)

		// When: getting the failure reason
		let reason = error.failureReason

		// Then: reason explains the technical issue
		#expect(reason != nil)
		#expect(reason?.contains(testKey) == true)
	}

	/// Test that noAddresses error explains why addresses are required.
	///
	/// The failure reason should explain that addresses are needed for
	/// routing traffic through the tunnel.
	@Test("No addresses error explains why addresses are required")
	func noAddressesFailureReason() {
		// Given: a noAddresses error
		let error = ConfigurationError.noAddresses

		// When: getting the failure reason
		let reason = error.failureReason

		// Then: reason explains the routing requirement
		#expect(reason != nil)
		#expect(reason?.lowercased().contains("routing") == true)
	}

	/// Test that invalidMTU error explains the valid MTU range.
	///
	/// The failure reason should specify the minimum and maximum MTU values
	/// and explain why the range exists.
	@Test("Invalid MTU error explains valid MTU range")
	func invalidMTUFailureReason() {
		// Given: an invalid MTU error
		let error = ConfigurationError.invalidMTU(mtu: 500)

		// When: getting the failure reason
		let reason = error.failureReason

		// Then: reason explains the valid range
		#expect(reason != nil)
		#expect(reason?.contains("1280") == true)
		#expect(reason?.contains("65535") == true)
	}

	/// Test that invalidKeepalive error explains the valid interval range.
	///
	/// The failure reason should specify the valid keepalive interval range
	/// and the special meaning of 0 (disabled).
	@Test("Invalid keepalive error explains valid interval range")
	func invalidKeepaliveFailureReason() {
		// Given: an invalid keepalive error
		let error = ConfigurationError.invalidKeepalive(interval: 60000)

		// When: getting the failure reason
		let reason = error.failureReason

		// Then: reason explains the valid range
		#expect(reason != nil)
		#expect(reason?.contains("1") == true || reason?.contains("65535") == true)
	}

	// MARK: - Recovery suggestion tests

	/// Test that noPeers error suggests adding a peer.
	///
	/// The recovery suggestion should guide users to add a peer configuration
	/// with the necessary components.
	@Test("No peers error suggests adding a peer")
	func noPeersRecoverySuggestion() {
		// Given: a noPeers error
		let error = ConfigurationError.noPeers

		// When: getting the recovery suggestion
		let suggestion = error.recoverySuggestion

		// Then: suggestion guides user to add a peer
		#expect(suggestion != nil)
		#expect(suggestion?.lowercased().contains("add") == true)
		#expect(suggestion?.lowercased().contains("peer") == true)
	}

	/// Test that duplicatePeerPublicKey error suggests removing duplicate.
	///
	/// The recovery suggestion should guide users to either remove the
	/// duplicate peer or ensure each peer has a unique key.
	@Test("Duplicate peer public key error suggests removing duplicate")
	func duplicatePeerPublicKeyRecoverySuggestion() {
		// Given: a duplicate key error
		let error = ConfigurationError.duplicatePeerPublicKey(publicKey: "test")

		// When: getting the recovery suggestion
		let suggestion = error.recoverySuggestion

		// Then: suggestion guides user to fix the duplicate
		#expect(suggestion != nil)
		#expect(suggestion?.lowercased().contains("unique") == true)
	}

	/// Test that noAddresses error suggests adding an address.
	///
	/// The recovery suggestion should guide users to add at least one
	/// IP address in CIDR notation with examples.
	@Test("No addresses error suggests adding an address")
	func noAddressesRecoverySuggestion() {
		// Given: a noAddresses error
		let error = ConfigurationError.noAddresses

		// When: getting the recovery suggestion
		let suggestion = error.recoverySuggestion

		// Then: suggestion provides guidance with examples
		#expect(suggestion != nil)
		#expect(suggestion?.lowercased().contains("add") == true)
		#expect(suggestion?.lowercased().contains("cidr") == true)
	}

	/// Test that invalidMTU error suggests valid MTU values.
	///
	/// The recovery suggestion should recommend appropriate MTU values
	/// like 1420 for standard Ethernet.
	@Test("Invalid MTU error suggests valid MTU values")
	func invalidMTURecoverySuggestion() {
		// Given: an invalid MTU error
		let error = ConfigurationError.invalidMTU(mtu: 500)

		// When: getting the recovery suggestion
		let suggestion = error.recoverySuggestion

		// Then: suggestion recommends appropriate values
		#expect(suggestion != nil)
		#expect(suggestion?.contains("1280") == true || suggestion?.contains("1420") == true)
	}

	/// Test that invalidKeepalive error suggests valid intervals.
	///
	/// The recovery suggestion should recommend common keepalive intervals
	/// like 25 seconds for NAT traversal or 0 to disable.
	@Test("Invalid keepalive error suggests valid intervals")
	func invalidKeepaliveRecoverySuggestion() {
		// Given: an invalid keepalive error
		let error = ConfigurationError.invalidKeepalive(interval: 60000)

		// When: getting the recovery suggestion
		let suggestion = error.recoverySuggestion

		// Then: suggestion recommends appropriate intervals
		#expect(suggestion != nil)
		#expect(suggestion?.contains("25") == true || suggestion?.contains("0") == true)
	}

	// MARK: - Equatable tests

	/// Test that identical noPeers errors are equal.
	///
	/// Equatable conformance should allow comparing errors for equality,
	/// which is useful for testing and error matching.
	@Test("Identical no peers errors are equal")
	func noPeersEquality() {
		// Given: two identical noPeers errors
		let error1 = ConfigurationError.noPeers
		let error2 = ConfigurationError.noPeers

		// Then: they should be equal
		#expect(error1 == error2)
	}

	/// Test that duplicatePeerPublicKey errors with same key are equal.
	///
	/// Errors with the same associated value should be considered equal.
	@Test("Duplicate peer public key errors with same key are equal")
	func duplicatePeerPublicKeyEquality() {
		// Given: two duplicate key errors with the same key
		let testKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
		let error1 = ConfigurationError.duplicatePeerPublicKey(publicKey: testKey)
		let error2 = ConfigurationError.duplicatePeerPublicKey(publicKey: testKey)

		// Then: they should be equal
		#expect(error1 == error2)
	}

	/// Test that duplicatePeerPublicKey errors with different keys are not equal.
	///
	/// Errors with different associated values should not be equal.
	@Test("Duplicate peer public key errors with different keys are not equal")
	func duplicatePeerPublicKeyInequality() {
		// Given: two duplicate key errors with different keys
		let error1 = ConfigurationError.duplicatePeerPublicKey(publicKey: "key1")
		let error2 = ConfigurationError.duplicatePeerPublicKey(publicKey: "key2")

		// Then: they should not be equal
		#expect(error1 != error2)
	}

	/// Test that invalidMTU errors with same value are equal.
	///
	/// Errors with the same MTU value should be considered equal.
	@Test("Invalid MTU errors with same value are equal")
	func invalidMTUEquality() {
		// Given: two invalid MTU errors with the same value
		let error1 = ConfigurationError.invalidMTU(mtu: 500)
		let error2 = ConfigurationError.invalidMTU(mtu: 500)

		// Then: they should be equal
		#expect(error1 == error2)
	}

	/// Test that invalidMTU errors with different values are not equal.
	///
	/// Errors with different MTU values should not be equal.
	@Test("Invalid MTU errors with different values are not equal")
	func invalidMTUInequality() {
		// Given: two invalid MTU errors with different values
		let error1 = ConfigurationError.invalidMTU(mtu: 500)
		let error2 = ConfigurationError.invalidMTU(mtu: 600)

		// Then: they should not be equal
		#expect(error1 != error2)
	}

	/// Test that different error cases are not equal.
	///
	/// Different error cases should never be equal even if they might have
	/// conceptually similar meanings.
	@Test("Different error cases are not equal")
	func differentCasesInequality() {
		// Given: errors of different cases
		let error1 = ConfigurationError.noPeers
		let error2 = ConfigurationError.noAddresses

		// Then: they should not be equal
		#expect(error1 != error2)
	}
}
