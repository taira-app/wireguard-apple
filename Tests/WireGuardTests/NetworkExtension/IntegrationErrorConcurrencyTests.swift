import Testing

@testable import WireGuard

/// Tests for IntegrationError concurrency safety.
///
/// In Swift 6, types that can be safely shared across concurrency boundaries
/// must conform to the Sendable protocol. This is critical for modern Swift
/// applications that use async/await and actors.
///
/// These tests verify that IntegrationError can be safely used in concurrent code,
/// such as passing errors between actors or returning them from async functions.
@Suite("Integration error concurrency tests")
struct IntegrationErrorConcurrencyTests {

	/// Test that IntegrationError can be sent across concurrency domains.
	///
	/// Sendable conformance means the error type can be safely shared between
	/// different actors and tasks without causing data races.
	///
	/// This test creates an error and passes it to a Task, which proves the
	/// compiler accepts it as Sendable. If the error wasn't Sendable, this
	/// code would fail to compile.
	@Test("IntegrationError can be sent across concurrency domains")
	func testSendableConformance() {
		// Create an error instance.
		let error = IntegrationError.noIPv4Address

		// Create a Task (which runs in a different concurrency domain).
		// If IntegrationError weren't Sendable, the compiler would reject this.
		Task {
			// Use the error in this task.
			// The underscore tells the compiler we're intentionally not using the value.
			_ = error
		}

		// If we reached here, the code compiled successfully.
		// This proves IntegrationError conforms to Sendable.
		#expect(true)
	}

	/// Test that IntegrationError with associated data is Sendable.
	///
	/// Errors with associated data (like String) are only Sendable if their
	/// associated data is also Sendable. Since String is Sendable, our errors
	/// with String associated data should be Sendable too.
	@Test("IntegrationError with associated data is Sendable")
	func testSendableWithAssociatedData() {
		// Create an error with associated data (a String).
		let error = IntegrationError.invalidRoute("10.0.0.0/8")

		// Pass it to a Task to verify Sendable conformance.
		Task {
			_ = error
		}

		// Compilation success proves Sendable conformance.
		#expect(true)
	}

	/// Test that IntegrationError can be returned from async functions.
	///
	/// Async functions often run in different execution contexts, so return types
	/// must be Sendable. This test verifies we can return IntegrationError from
	/// an async function.
	@Test("IntegrationError can be returned from async functions")
	func testAsyncFunctionReturn() async {
		// Define an async function that returns an IntegrationError.
		// The fact that this compiles proves IntegrationError is Sendable.
		func generateError() async -> IntegrationError {
			// Return an error instance.
			return IntegrationError.noIPv6Address
		}

		// Call the async function.
		let error = await generateError()

		// Verify we got the expected error.
		#expect(error == IntegrationError.noIPv6Address)
	}

	/// Test that IntegrationError can be thrown from async functions.
	///
	/// Many async functions throw errors. The Error protocol requires types
	/// to be Sendable in Swift 6. This test verifies we can throw IntegrationError
	/// from async functions.
	@Test("IntegrationError can be thrown from async functions")
	func testAsyncFunctionThrow() async {
		// Define an async function that throws an IntegrationError.
		func throwError() async throws {
			// Throw an error.
			throw IntegrationError.settingsGenerationFailed("test error")
		}

		// Try to call the function and catch the error.
		do {
			try await throwError()
			// If we reach here, the function didn't throw (unexpected).
			Issue.record("Expected function to throw")
		} catch let error as IntegrationError {
			// We caught the error successfully.
			// Verify it's the error we expect.
			#expect(error == IntegrationError.settingsGenerationFailed("test error"))
		} catch {
			// We caught a different error type (unexpected).
			Issue.record("Caught unexpected error type: \(error)")
		}
	}

	/// Test that IntegrationError can be used in actor-isolated code.
	///
	/// Actors are a key feature of Swift concurrency. Data passed to or from
	/// actors must be Sendable. This test verifies IntegrationError works with actors.
	@Test("IntegrationError can be used with actors")
	func testActorIsolation() async {
		// Define an actor that stores an IntegrationError.
		// Actors automatically isolate their state to prevent data races.
		actor ErrorStore {
			// Store an error.
			// This is only allowed if IntegrationError is Sendable.
			private var storedError: IntegrationError?

			// Store an error.
			func store(_ error: IntegrationError) {
				self.storedError = error
			}

			// Retrieve the stored error.
			func retrieve() -> IntegrationError? {
				return self.storedError
			}
		}

		// Create an actor instance.
		let store = ErrorStore()

		// Store an error in the actor.
		await store.store(IntegrationError.packetFlowError("test"))

		// Retrieve the error from the actor.
		let retrieved = await store.retrieve()

		// Verify we got the same error back.
		#expect(retrieved == IntegrationError.packetFlowError("test"))
	}
}
