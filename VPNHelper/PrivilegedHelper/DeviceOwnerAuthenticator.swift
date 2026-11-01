import LocalAuthentication

@MainActor
protocol DeviceOwnerAuthenticating {
    func authenticate(reason: String) async throws
}

struct DeviceOwnerAuthenticator: DeviceOwnerAuthenticating {
    func authenticate(reason: String) async throws {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw error ?? HelperFailure(message: "macOS could not authenticate the current user.")
        }
        // This policy lets macOS offer Touch ID and the Mac password fallback.
        let authenticated = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        guard authenticated else {
            throw HelperFailure(message: "Authentication was cancelled. The VPN tunnel was not started.")
        }
    }
}

@MainActor
extension DeviceOwnerAuthenticating {
    func authorize<T>(reason: String, operation: () async throws -> T) async throws -> T {
        try await authenticate(reason: reason)
        try Task.checkCancellation()
        return try await operation()
    }
}
