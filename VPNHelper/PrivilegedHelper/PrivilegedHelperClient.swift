import Foundation
import ServiceManagement

nonisolated enum HelperInstallationState: Equatable {
    case unavailable(String)
    case notInstalled
    case requiresApproval
    case ready

    var message: String {
        switch self {
        case .unavailable(let reason): reason
        case .notInstalled: "Set up Touch ID for VPN connections."
        case .requiresApproval: "Approve VPN Helper in System Settings → General → Login Items & Extensions, then finish setup."
        case .ready: "Touch ID or your Mac password can authorize the VPN."
        }
    }
}

@MainActor
final class PrivilegedHelperClient {
    var onOutput: ((Data) -> Void)?
    var onExit: ((Int32) -> Void)?
    var onFailure: ((String) -> Void)?
    private var connection: NSXPCConnection?
    private var receiver: HelperEventReceiver?
    private let authenticator: any DeviceOwnerAuthenticating
    private let service = SMAppService.daemon(plistName: HelperConstants.plistName)

    init(authenticator: (any DeviceOwnerAuthenticating)? = nil) {
        self.authenticator = authenticator ?? DeviceOwnerAuthenticator()
    }

    var installationState: HelperInstallationState {
        do {
            _ = try HelperSecurity.signingRequirement()
        } catch {
            return .unavailable(error.localizedDescription)
        }
        switch service.status {
        case .enabled: return .ready
        case .requiresApproval: return .requiresApproval
        case .notRegistered, .notFound: return .notInstalled
        @unknown default: return .unavailable("macOS returned an unknown helper status.")
        }
    }

    var isPreferred: Bool {
        UserDefaults.standard.bool(forKey: "usePrivilegedHelper") && installationState == .ready
    }

    func install() async throws {
        _ = try HelperSecurity.signingRequirement()
        guard Bundle.main.bundleURL.path == "/Applications/VPNHelper.app" else {
            throw HelperFailure(message: "Install VPN Helper in /Applications before setting up Touch ID.")
        }
        if service.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
            return
        }
        if service.status == .enabled {
            do {
                try await checkReadiness()
                UserDefaults.standard.set(true, forKey: "usePrivilegedHelper")
                return
            } catch {
                // A daemon from the previous signed build must be replaced.
            }
            disconnect()
            try await service.unregister()
        }
        try service.register()
        if service.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
            return
        }
        guard service.status == .enabled else {
            throw HelperFailure(message: "The VPN helper was not enabled by macOS.")
        }
        try await checkReadiness()
        UserDefaults.standard.set(true, forKey: "usePrivilegedHelper")
    }

    func usePassword() {
        UserDefaults.standard.set(false, forKey: "usePrivilegedHelper")
        disconnect()
    }

    func startTunnel(using session: VPNAuthSession) async throws {
        try await checkReadiness()
        try await authenticator.authorize(reason: "Allow VPN Helper to establish your VPN connection.") {
            _ = try await request { proxy, reply in
                proxy.startTunnel(cookie: session.cookie, connectURL: session.connectURL, fingerprint: session.fingerprint, resolve: session.resolve, reply: reply)
            }
        }
    }

    func stopTunnel() async throws {
        // The authenticated connection may always clean up its own tunnel.
        _ = try await request { proxy, reply in proxy.stopTunnel(reply: reply) }
    }

    func repairNetwork() async throws -> [String] {
        try await checkReadiness()
        return try await authenticator.authorize(reason: "Allow VPN Helper to repair your Mac's network settings.") {
            try await request { proxy, reply in proxy.repairNetwork(reply: reply) }
        }
    }

    private func checkReadiness() async throws {
        let version = try await request { proxy, reply in proxy.ping(reply: reply) }
        guard version == [HelperConstants.protocolVersion] else {
            throw HelperFailure(message: "The VPN helper must be updated. Run Touch ID setup again.")
        }
    }

    private func connect() throws -> NSXPCConnection {
        if let connection { return connection }
        let requirement = try HelperSecurity.signingRequirement()
        let connection = NSXPCConnection(machServiceName: HelperConstants.machService, options: .privileged)
        connection.setCodeSigningRequirement(requirement)
        connection.remoteObjectInterface = NSXPCInterface(with: VPNPrivilegedHelperProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: VPNPrivilegedClientProtocol.self)
        let receiver = HelperEventReceiver(
            output: { [weak self] data in self?.onOutput?(data) },
            exit: { [weak self] status in self?.onExit?(status) }
        )
        connection.exportedObject = receiver
        connection.invalidationHandler = { [weak self] in
            Task { @MainActor [weak self] in
                self?.connection = nil
                self?.receiver = nil
                self?.onFailure?("The privileged VPN helper disconnected.")
            }
        }
        connection.interruptionHandler = { [weak self] in
            Task { @MainActor [weak self] in
                self?.connection?.invalidate()
            }
        }
        self.connection = connection
        self.receiver = receiver
        connection.resume()
        return connection
    }

    private func disconnect() {
        connection?.invalidationHandler = nil
        connection?.interruptionHandler = nil
        connection?.invalidate()
        connection = nil
        receiver = nil
    }

    private func request(_ send: (VPNPrivilegedHelperProtocol, @escaping ([String], String?) -> Void) -> Void) async throws -> [String] {
        let connection = try connect()
        return try await withCheckedThrowingContinuation { continuation in
            let reply = HelperReply(continuation)
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                reply.finish(.failure(error))
            }) as? VPNPrivilegedHelperProtocol else {
                reply.finish(.failure(HelperFailure(message: "Could not contact the VPN helper.")))
                return
            }
            send(proxy) { lines, message in
                if let message {
                    reply.finish(.failure(HelperFailure(message: message)))
                } else if connection.effectiveUserIdentifier != 0 {
                    reply.finish(.failure(HelperFailure(message: "The VPN helper is not running as root.")))
                    connection.invalidate()
                } else {
                    reply.finish(.success(lines))
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                if reply.finish(.failure(HelperFailure(message: "The VPN helper did not respond. Check its approval in System Settings or run setup again."))) {
                    connection.invalidate()
                }
            }
        }
    }
}

nonisolated private final class HelperEventReceiver: NSObject, VPNPrivilegedClientProtocol, Sendable {
    private let output: @MainActor @Sendable (Data) -> Void
    private let exit: @MainActor @Sendable (Int32) -> Void

    init(output: @escaping @MainActor @Sendable (Data) -> Void, exit: @escaping @MainActor @Sendable (Int32) -> Void) {
        self.output = output
        self.exit = exit
    }

    func tunnelOutput(_ data: Data) {
        DispatchQueue.main.async { self.output(data) }
    }

    func tunnelExited(_ status: Int32) {
        DispatchQueue.main.async { self.exit(status) }
    }
}

/// XPC error, reply, and timeout callbacks can race. The lock ensures exactly
/// one continuation resumption; no mutable state escapes this object.
nonisolated private final class HelperReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[String], Error>?

    init(_ continuation: CheckedContinuation<[String], Error>) {
        self.continuation = continuation
    }

    @discardableResult
    func finish(_ result: Result<[String], Error>) -> Bool {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
        return pending != nil
    }
}
