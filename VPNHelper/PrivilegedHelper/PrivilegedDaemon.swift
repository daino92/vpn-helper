import Foundation
import Darwin
import Darwin.membership
import SystemConfiguration

nonisolated final class PrivilegedDaemon: NSObject, NSXPCListenerDelegate {
    private let requirement: String
    private let controller = PrivilegedTunnelController()

    init(requirement: String) {
        self.requirement = requirement
    }

    static func run() -> Never {
        guard geteuid() == 0, let requirement = try? HelperSecurity.signingRequirement() else {
            exit(EXIT_FAILURE)
        }
        let delegate = PrivilegedDaemon(requirement: requirement)
        let listener = NSXPCListener(machServiceName: HelperConstants.machService)
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime((delegate, listener)) {
            RunLoop.current.run()
        }
        exit(EXIT_FAILURE)
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        var consoleUID: uid_t = 0
        var consoleGID: gid_t = 0
        guard SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) != nil,
              consoleUID != 0, connection.effectiveUserIdentifier == consoleUID,
              Self.isAdministrator(consoleUID) else {
            return false
        }
        // NSXPC checks each message against the signing requirement, avoiding
        // a PID-based signature check that could race with process reuse.
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: VPNPrivilegedHelperProtocol.self)
        connection.remoteObjectInterface = NSXPCInterface(with: VPNPrivilegedClientProtocol.self)
        let session = PrivilegedSession(connection: connection, controller: controller)
        connection.exportedObject = session
        connection.invalidationHandler = { session.invalidate() }
        connection.interruptionHandler = { session.invalidate() }
        connection.resume()
        return true
    }

    fileprivate static func isAdministrator(_ uid: uid_t) -> Bool {
        var user = UUID().uuid
        var admin = UUID().uuid
        var member: Int32 = 0
        return mbr_uid_to_uuid(uid, &user) == 0 &&
            mbr_gid_to_uuid(80, &admin) == 0 &&
            mbr_check_membership(&user, &admin, &member) == 0 && member != 0
    }
}

nonisolated private final class PrivilegedSession: NSObject, VPNPrivilegedHelperProtocol, @unchecked Sendable {
    let identifier = UUID()
    // Assigned only at initialization. NSXPCConnection and Objective-C weak
    // access are thread-safe; tunnel state stays on the controller queue.
    private weak var connection: NSXPCConnection?
    private let controller: PrivilegedTunnelController
    private let userID: uid_t
    // Read and changed only on the controller queue, including invalidation.
    private var invalidated = false

    init(connection: NSXPCConnection, controller: PrivilegedTunnelController) {
        self.connection = connection
        self.controller = controller
        self.userID = connection.effectiveUserIdentifier
    }

    func ping(reply: @escaping ([String], String?) -> Void) {
        controller.queue.async {
            do {
                try self.requireActiveSession()
                try self.controller.validateTools()
                reply([HelperConstants.protocolVersion], nil)
            } catch {
                reply([], error.localizedDescription)
            }
        }
    }

    func startTunnel(cookie: String, connectURL: String, fingerprint: String, resolve: String?, reply: @escaping ([String], String?) -> Void) {
        controller.queue.async {
            do {
                try self.requireActiveSession()
                try HelperPolicy.validateSession(cookie: cookie, connectURL: connectURL, fingerprint: fingerprint, resolve: resolve)
                try self.controller.start(cookie: cookie, connectURL: connectURL, fingerprint: fingerprint, resolve: resolve, owner: self)
                reply([], nil)
            } catch {
                reply([], error.localizedDescription)
            }
        }
    }

    func stopTunnel(reply: @escaping ([String], String?) -> Void) {
        controller.queue.async {
            do {
                try self.controller.stop(owner: self.identifier)
                reply([], nil)
            } catch {
                reply([], error.localizedDescription)
            }
        }
    }

    func repairNetwork(reply: @escaping ([String], String?) -> Void) {
        controller.queue.async {
            do {
                try self.requireActiveSession()
                reply(try self.controller.repairNetwork(), nil)
            } catch {
                reply([], error.localizedDescription)
            }
        }
    }

    func invalidate() {
        controller.queue.async {
            self.invalidated = true
            try? self.controller.stop(owner: self.identifier)
        }
    }

    private func requireActiveSession() throws {
        var consoleUID: uid_t = 0
        var consoleGID: gid_t = 0
        guard !invalidated, connection != nil,
              SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) != nil,
              consoleUID == userID, PrivilegedDaemon.isAdministrator(userID) else {
            throw HelperFailure(message: "The request no longer belongs to the active administrator session.")
        }
    }

    func output(_ data: Data) {
        let client = connection?.remoteObjectProxyWithErrorHandler { _ in } as? VPNPrivilegedClientProtocol
        client?.tunnelOutput(data)
    }

    func exited(_ status: Int32) {
        let client = connection?.remoteObjectProxyWithErrorHandler { _ in } as? VPNPrivilegedClientProtocol
        client?.tunnelExited(status)
    }
}

nonisolated private final class PrivilegedTunnelController: @unchecked Sendable {
    // Process and owner state are confined to queue. Foundation callbacks
    // enqueue work before reading or mutating that state.
    let queue = DispatchQueue(label: "VPNHelper.PrivilegedTunnel")
    private var process: Process?
    private var outputPipe: Pipe?
    private weak var owner: PrivilegedSession?
    private var ownerIdentifier: UUID?
    private let openconnect = HelperConstants.toolDirectory + "/openconnect"
    private let vpnSlice = HelperConstants.toolDirectory + "/vpn-slice"
    private let environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/root", "LANG": "C", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"]

    func validateTools() throws {
        do {
            try HelperPolicy.validateManagedTool(openconnect)
            try HelperPolicy.validateManagedTool(vpnSlice)
            try HelperPolicy.validateToolDirectory()
        } catch {
            throw HelperFailure(message: "The managed VPN toolchain is not installed or is not secure. Install the root-managed toolchain before enabling Touch ID. The password connection remains available. \(error.localizedDescription)")
        }
    }

    func start(cookie: String, connectURL: String, fingerprint: String, resolve: String?, owner: PrivilegedSession) throws {
        guard process == nil else {
            throw HelperFailure(message: "A privileged VPN tunnel is already running.")
        }
        try validateTools()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: openconnect)
        let script = "'\(vpnSlice)' --domains-vpn-dns=ote.gr,cosmote.gr,azure.com 10.0.0.0/8"
        var arguments = ["--protocol=fortinet", "--cookie-on-stdin", "--script", script, "--disable-ipv6", "--servercert", fingerprint]
        if let resolve { arguments += ["--resolve", resolve] }
        arguments.append(connectURL)
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output
        self.owner = owner
        ownerIdentifier = owner.identifier
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.queue.async { self?.owner?.output(data) }
        }
        process.terminationHandler = { [weak self] finished in
            self?.queue.async {
                guard let self, self.process === finished else { return }
                output.fileHandleForReading.readabilityHandler = nil
                let remaining = output.fileHandleForReading.readDataToEndOfFile()
                if !remaining.isEmpty { self.owner?.output(remaining) }
                self.owner?.exited(finished.terminationStatus)
                self.process = nil
                self.outputPipe = nil
                self.owner = nil
                self.ownerIdentifier = nil
            }
        }
        do {
            try process.run()
            self.process = process
            outputPipe = output
            try input.fileHandleForWriting.write(contentsOf: Data((cookie + "\n").utf8))
            try input.fileHandleForWriting.close()
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            if process.isRunning { process.terminate() }
            throw error
        }
    }

    func stop(owner identifier: UUID) throws {
        guard let process else { return }
        guard ownerIdentifier == identifier else {
            throw HelperFailure(message: "This connection does not own the VPN tunnel.")
        }
        guard process.isRunning else { return }
        let pid = process.processIdentifier
        process.interrupt()
        queue.asyncAfter(deadline: .now() + 4) { [weak self] in
            guard self?.process === process, process.isRunning else { return }
            process.terminate()
            self?.queue.asyncAfter(deadline: .now() + 4) { [weak self] in
                guard self?.process === process, process.isRunning else { return }
                kill(pid, SIGKILL)
            }
        }
    }

    func repairNetwork() throws -> [String] {
        var logs: [String] = []
        for (executable, arguments) in [("/usr/bin/dscacheutil", ["-flushcache"]), ("/usr/bin/killall", ["-HUP", "mDNSResponder"])] {
            let command = Process()
            command.executableURL = URL(fileURLWithPath: executable)
            command.arguments = arguments
            command.environment = environment
            command.standardOutput = FileHandle.nullDevice
            command.standardError = FileHandle.nullDevice
            try command.run()
            command.waitUntilExit()
            guard command.terminationStatus == 0 else {
                throw HelperFailure(message: "Network repair failed while running \(executable).")
            }
            logs.append("OK: \(executable) \(arguments.joined(separator: " "))")
        }
        return logs
    }
}
