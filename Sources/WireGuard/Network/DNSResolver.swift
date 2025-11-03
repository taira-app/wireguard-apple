import Foundation
import Network

/// A thread-safe boolean wrapper for use in concurrent contexts.
///
/// This class provides a Sendable-compliant way to manage a boolean flag
/// that can be atomically checked and set from multiple threads.
private final class ResumptionFlag: @unchecked Sendable {
	/// The underlying boolean value.
	private var value: Bool

	/// Lock to ensure thread-safe access.
	private let lock = NSLock()

	/// Creates a new resumption flag with the specified initial value.
	///
	/// - Parameter value: The initial boolean value.
	init(_ value: Bool) {
		self.value = value
	}

	/// Atomically sets the flag to true if it's currently false.
	///
	/// - Returns: `true` if the flag was false and is now set to true, `false` if it was already true.
	func setIfFalse() -> Bool {
		lock.lock()

		defer { lock.unlock() }

		if !value {
			value = true
			return true
		}

		return false
	}
}

/// An actor for performing asynchronous DNS resolution.
///
/// The DNS resolver provides async/await based hostname resolution using Apple's
/// Network framework. It resolves hostnames to IP addresses with timeout support.
///
/// ## Usage
///
/// Resolve a hostname to IP addresses:
///
/// ```swift
/// let resolver = DNSResolver()
/// do {
///     let hosts = try await resolver.resolve("example.com")
///     // hosts contains Endpoint.Host values (.ipv4 or .ipv6)
/// } catch {
///     print("Resolution failed: \(error)")
/// }
/// ```
///
/// ## Thread safety
///
/// This type is an actor and provides thread-safe DNS resolution operations.
public actor DNSResolver {
	/// The default timeout for DNS resolution in seconds.
	public static let defaultTimeout: TimeInterval = 30.0

	/// The timeout for DNS resolution operations.
	private let timeout: TimeInterval

	/// Creates a new DNS resolver.
	///
	/// - Parameter timeout: The maximum time to wait for resolution (default: 30 seconds).
	public init(timeout: TimeInterval = DNSResolver.defaultTimeout) {
		self.timeout = timeout
	}

	/// Resolves a hostname to a list of IP addresses.
	///
	/// This method performs asynchronous DNS resolution and returns both IPv4 and
	/// IPv6 addresses if available.
	///
	/// - Parameter hostname: The hostname to resolve.
	/// - Returns: An array of resolved host addresses.
	/// - Throws: `NetworkError.resolutionFailed` if resolution fails,
	///           `NetworkError.resolutionTimeout` if the operation times out.
	public func resolve(_ hostname: String) async throws -> [Endpoint.Host] {
		// Use NWConnection to resolve the hostname
		// This is a lightweight way to resolve hostnames using Network framework
		let host = NWEndpoint.Host(hostname)
		let port = NWEndpoint.Port(rawValue: 0)!  // Port doesn't matter for resolution

		return try await withThrowingTaskGroup(of: [Endpoint.Host].self) { group in
			// Add the resolution task
			group.addTask {
				try await self.performResolution(host: host, port: port, hostname: hostname)
			}

			// Add the timeout task
			group.addTask {
				try await Task.sleep(for: .seconds(self.timeout))
				throw NetworkError.resolutionTimeout
			}

			// Wait for the first task to complete
			guard let result = try await group.next() else {
				throw NetworkError.resolutionFailed(hostname)
			}

			// Cancel the remaining task
			group.cancelAll()

			return result
		}
	}

	/// Performs the actual DNS resolution using NWConnection.
	///
	/// - Parameters:
	///   - host: The NWEndpoint.Host to resolve.
	///   - port: A dummy port for the connection.
	///   - hostname: The original hostname string for error reporting.
	/// - Returns: An array of resolved host addresses.
	/// - Throws: `NetworkError.resolutionFailed` if resolution fails.
	private func performResolution(host: NWEndpoint.Host, port: NWEndpoint.Port, hostname: String) async throws
		-> [Endpoint.Host] {
		return try await withCheckedThrowingContinuation { continuation in
			let parameters = NWParameters.udp
			let connection = NWConnection(host: host, port: port, using: parameters)
			let hasResumed = ResumptionFlag(false)

			connection.stateUpdateHandler = { [weak connection] state in
				Self.handleConnectionState(
					state,
					connection: connection,
					hostname: hostname,
					hasResumed: hasResumed,
					continuation: continuation
				)
			}

			connection.start(queue: .global())
		}
	}

	/// Handles NWConnection state updates during DNS resolution.
	///
	/// - Parameters:
	///   - state: The current connection state.
	///   - connection: The network connection (weak reference).
	///   - hostname: The hostname being resolved (for error messages).
	///   - hasResumed: Flag to ensure continuation is resumed only once.
	///   - continuation: The checked continuation to resume.
	private static func handleConnectionState(
		_ state: NWConnection.State,
		connection: NWConnection?,
		hostname: String,
		hasResumed: ResumptionFlag,
		continuation: CheckedContinuation<[Endpoint.Host], Error>
	) {
		switch state {
		case .ready:
			handleReadyState(
				connection, hostname: hostname, hasResumed: hasResumed, continuation: continuation)

		case .failed, .cancelled:
			if hasResumed.setIfFalse() {
				continuation.resume(throwing: NetworkError.resolutionFailed(hostname))
			}
			connection?.cancel()

		case .waiting, .preparing, .setup:
			break

		@unknown default:
			break
		}
	}

	/// Handles the ready state of the connection by extracting resolved addresses.
	///
	/// - Parameters:
	///   - connection: The network connection (weak reference).
	///   - hostname: The hostname being resolved (for error messages).
	///   - hasResumed: Flag to ensure continuation is resumed only once.
	///   - continuation: The checked continuation to resume.
	private static func handleReadyState(
		_ connection: NWConnection?,
		hostname: String,
		hasResumed: ResumptionFlag,
		continuation: CheckedContinuation<[Endpoint.Host], Error>
	) {
		guard let resolvedEndpoint = connection?.currentPath?.remoteEndpoint else {
			if hasResumed.setIfFalse() {
				continuation.resume(throwing: NetworkError.resolutionFailed(hostname))
			}
			connection?.cancel()
			return
		}

		let hosts = extractHosts(from: resolvedEndpoint)
		if !hosts.isEmpty, hasResumed.setIfFalse() {
			continuation.resume(returning: hosts)
		} else if hasResumed.setIfFalse() {
			continuation.resume(throwing: NetworkError.resolutionFailed(hostname))
		}
		connection?.cancel()
	}

	/// Extracts host addresses from an NWEndpoint.
	///
	/// This is a static method to avoid actor isolation issues when called from
	/// the NWConnection state handler.
	///
	/// - Parameter endpoint: The network endpoint.
	/// - Returns: An array of host addresses extracted from the endpoint.
	private static func extractHosts(from endpoint: NWEndpoint) -> [Endpoint.Host] {
		var hosts: [Endpoint.Host] = []

		switch endpoint {
		case .hostPort(let host, _):
			switch host {
			case .ipv4(let ipv4):
				hosts.append(.ipv4(ipv4))
			case .ipv6(let ipv6):
				hosts.append(.ipv6(ipv6))
			case .name:
				// Should not happen after resolution, but handle it
				break
			@unknown default:
				break
			}
		default:
			break
		}

		return hosts
	}
}
