//
//  VPNService.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import Foundation
import Darwin

final class VPNService: VPNServiceProtocol {
    var onLog: ((String) -> Void)?
    var onAwaitingOTP: (() -> Void)?
    var onAuthenticated: ((VPNAuthSession) -> Void)?
    var onConnected: (() -> Void)?
    var onDisconnected: (() -> Void)?
    var onError: ((String) -> Void)?

    private let sudoPath = "/usr/bin/sudo"
    private let osascriptPath = "/usr/bin/osascript"
    private let pgrepPath = "/usr/bin/pgrep"
    private let runtimeResolver: VPNRuntimeResolver
    private var selectedRuntime: VPNRuntime?
    private let askpassScriptPath = FileManager.default.temporaryDirectory
        .appendingPathComponent("vpnhelper-askpass-\(UUID().uuidString).sh").path
    private let pidFilePath = "/tmp/vpnhelper-openconnect.pid"

    private let queue = DispatchQueue(label: "VPNService.PTYQueue")

    private enum SessionMode {
        case authenticating
        case tunnel
    }

    private var process: Process?
    private var masterHandle: FileHandle?
    private var sessionMode: SessionMode?

    private var fullOutput: String = ""
    private var bufferedChunk: String = ""

    private var savedPassword: String = ""
    private var hasSentPassword = false
    private var awaitingOTP = false
    private var disconnectRequested = false
    private var tunnelConnected = false
    private var tunnelPID: Int32?

    private var disconnectContinuation: CheckedContinuation<Void, Error>?

    init(runtimeResolver: VPNRuntimeResolver? = nil) {
        self.runtimeResolver = runtimeResolver ?? VPNRuntimeResolver()
    }

    func requestAdminAccess() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: osascriptPath)
        process.arguments = [
            "-e",
            #"do shell script "/usr/bin/true" with administrator privileges"#
        ]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        let result = try await runProcessAndCaptureOutput(process, pipe: pipe)

        if result.status != 0 {
            let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)

            throw NSError(
                domain: "VPNService",
                code: 900,
                userInfo: [
                    NSLocalizedDescriptionKey: output.isEmpty
                        ? "Administrator access was not granted."
                        : output
                ]
            )
        }
    }

    func startLogin(email: String, password: String) async throws {
        guard process == nil else {
            throw NSError(
                domain: "VPNService",
                code: 100,
                userInfo: [NSLocalizedDescriptionKey: "A VPN session is already running."]
            )
        }

        let runtime = try runtimeResolver.resolve()
        selectedRuntime = runtime
        let openconnectPath = runtime.openconnect.path
        emitLog(runtime.logDescription)

        resetSessionState()
        savedPassword = password
        sessionMode = .authenticating

        let (master, slave) = try makePTY()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: openconnectPath)
        process.arguments = runtime.certificateArguments + [
            "--authenticate",
            "--protocol=fortinet",
            "--resolve", "vpnaccess.ote.gr:195.167.99.229",
            "https://vpnaccess.ote.gr/",
            "-u", email
        ]

        var env = runtime.environment(from: ProcessInfo.processInfo.environment)
        env["TERM"] = "xterm-256color"
        process.environment = env

        process.standardInput = slave
        process.standardOutput = slave
        process.standardError = slave

        process.terminationHandler = { [weak self] process in
            self?.queue.async {
                self?.handleProcessTermination(status: process.terminationStatus)
            }
        }

        try process.run()
        slave.closeFile()

        self.process = process
        self.masterHandle = master

        emitLog("Started live VPN authentication session.")

        master.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }

            let text = String(decoding: data, as: UTF8.self)

            self?.queue.async {
                self?.handleIncomingText(text)
            }
        }
    }

    func submitOTP(_ otp: String) async throws {
        let trimmed = otp.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmed.isEmpty else {
            throw NSError(
                domain: "VPNService",
                code: 101,
                userInfo: [NSLocalizedDescriptionKey: "OTP cannot be empty."]
            )
        }

        guard process != nil, masterHandle != nil else {
            throw NSError(
                domain: "VPNService",
                code: 102,
                userInfo: [NSLocalizedDescriptionKey: "No active VPN authentication session."]
            )
        }

        guard awaitingOTP else {
            throw NSError(
                domain: "VPNService",
                code: 103,
                userInfo: [NSLocalizedDescriptionKey: "VPN session is not currently waiting for an OTP."]
            )
        }

        awaitingOTP = false
        try writeToSession(trimmed + "\n")
        emitLog("OTP sent to the live VPN session.")
    }

    func startTunnel(using session: VPNAuthSession) async throws {
        guard process == nil else {
            throw NSError(
                domain: "VPNService",
                code: 106,
                userInfo: [NSLocalizedDescriptionKey: "Another VPN session is already running."]
            )
        }

        let runtime = try selectedRuntime ?? runtimeResolver.resolve()
        let openconnectPath = runtime.openconnect.path
        let vpnSlicePath = runtime.vpnSlice.path

        guard FileManager.default.fileExists(atPath: sudoPath) else {
            throw NSError(
                domain: "VPNService",
                code: 403,
                userInfo: [NSLocalizedDescriptionKey: "sudo was not found at \(sudoPath)"]
            )
        }

        guard FileManager.default.fileExists(atPath: openconnectPath) else {
            throw NSError(
                domain: "VPNService",
                code: 404,
                userInfo: [NSLocalizedDescriptionKey: "openconnect was not found at \(openconnectPath)"]
            )
        }

        guard FileManager.default.fileExists(atPath: vpnSlicePath) else {
            throw NSError(
                domain: "VPNService",
                code: 405,
                userInfo: [NSLocalizedDescriptionKey: "vpn-slice was not found at \(vpnSlicePath)"]
            )
        }

        try await ensureAskpassScript()

        resetSessionState()
        sessionMode = .tunnel

        let scriptCommand = runtime.splitTunnelScript

        var args: [String] = [
            "-A",
            openconnectPath
        ] + runtime.certificateArguments + [
            "--protocol=fortinet",
            "--cookie-on-stdin",
            "--script", scriptCommand,
            "--disable-ipv6",
            "--servercert", session.fingerprint,
            "--pid-file", pidFilePath
        ]

        if let resolve = session.resolve, !resolve.isEmpty {
            args.append("--resolve")
            args.append(resolve)
        }

        args.append(session.connectURL)

        let (master, slave) = try makePTY()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: sudoPath)
        process.arguments = args

        var env = runtime.environment(from: ProcessInfo.processInfo.environment)
        env["TERM"] = "xterm-256color"
        env["SUDO_ASKPASS"] = askpassScriptPath
        process.environment = env

        let stdinPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = slave
        process.standardError = slave

        process.terminationHandler = { [weak self] process in
            self?.queue.async {
                self?.handleProcessTermination(status: process.terminationStatus)
            }
        }

        try process.run()
        slave.closeFile()

        self.process = process
        self.masterHandle = master

        emitLog("Started privileged VPN tunnel process.")
        emitLog("Running openconnect with sudo askpass.")
        emitLog("Using vpn-slice for split tunneling.")

        if let cookieData = (session.cookie + "\n").data(using: .utf8) {
            stdinPipe.fileHandleForWriting.write(cookieData)
        }
        try? stdinPipe.fileHandleForWriting.close()

        master.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }

            let text = String(decoding: data, as: UTF8.self)

            self?.queue.async {
                self?.handleIncomingText(text)
            }
        }
    }

    func disconnect() async throws {
        if sessionMode == .authenticating, let process {
            disconnectRequested = true
            process.terminate()
            return
        }
        disconnectRequested = true
        emitLog("Disconnect requested. Looking up real openconnect PID...")

        guard let pid = await resolveTunnelPID() else {
            disconnectRequested = false
            throw NSError(
                domain: "VPNService",
                code: 702,
                userInfo: [NSLocalizedDescriptionKey: "Could not determine real openconnect PID from pid-file or child process lookup."]
            )
        }

        emitLog("Sending SIGINT to openconnect PID \(pid)...")

        try await ensureAskpassScript()

        let intResult = try await runSudoCommand([
            "-A", "/bin/kill", "-INT", String(pid)
        ])

        if intResult.status != 0 {
            disconnectRequested = false
            throw NSError(
                domain: "VPNService",
                code: 701,
                userInfo: [
                    NSLocalizedDescriptionKey: intResult.output.isEmpty
                        ? "Failed to interrupt VPN process \(pid)."
                        : intResult.output
                ]
            )
        }

        if await waitForProcessExit(pid: pid, timeoutSeconds: 4.0) {
            return
        }

        emitLog("SIGINT did not stop PID \(pid). Sending SIGTERM...")

        let termResult = try await runSudoCommand([
            "-A", "/bin/kill", "-TERM", String(pid)
        ])

        if termResult.status != 0 {
            disconnectRequested = false
            throw NSError(
                domain: "VPNService",
                code: 703,
                userInfo: [
                    NSLocalizedDescriptionKey: termResult.output.isEmpty
                        ? "Failed to terminate VPN process \(pid)."
                        : termResult.output
                ]
            )
        }

        if await waitForProcessExit(pid: pid, timeoutSeconds: 4.0) {
            return
        }

        emitLog("SIGTERM did not stop PID \(pid). Sending SIGKILL...")

        let killResult = try await runSudoCommand([
            "-A", "/bin/kill", "-KILL", String(pid)
        ])

        if killResult.status != 0 {
            disconnectRequested = false
            throw NSError(
                domain: "VPNService",
                code: 704,
                userInfo: [
                    NSLocalizedDescriptionKey: killResult.output.isEmpty
                        ? "Failed to force kill VPN process \(pid)."
                        : killResult.output
                ]
            )
        }

        if await waitForProcessExit(pid: pid, timeoutSeconds: 2.0) {
            return
        }

        disconnectRequested = false
        throw NSError(
            domain: "VPNService",
            code: 705,
            userInfo: [NSLocalizedDescriptionKey: "VPN process \(pid) is still running after SIGINT, SIGTERM, and SIGKILL."]
        )
    }

    func fixNetwork() async throws -> [String] {
        try await ensureAskpassScript()

        let commands: [[String]] = [
            ["-A", "/usr/bin/killall", "-HUP", "mDNSResponder"],
            ["-A", "/usr/bin/dscacheutil", "-flushcache"]
        ]

        var logs: [String] = []

        for command in commands {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: sudoPath)
            proc.arguments = command

            var env = ProcessInfo.processInfo.environment
            env["SUDO_ASKPASS"] = askpassScriptPath
            proc.environment = env

            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = pipe

            let result = try await runProcessAndCaptureOutput(proc, pipe: pipe)

            let joined = ([sudoPath] + command).joined(separator: " ")
            if result.status == 0 {
                logs.append("OK: \(joined)")
            } else {
                let message = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
                logs.append("FAILED: \(joined)\(message.isEmpty ? "" : " -> \(message)")")
            }
        }

        return logs
    }

    private func runProcessAndCaptureOutput(_ process: Process, pipe: Pipe) async throws -> (status: Int32, output: String) {
        let status = try await withCheckedThrowingContinuation { continuation in
            process.terminationHandler = { proc in
                continuation.resume(returning: proc.terminationStatus)
            }

            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                continuation.resume(throwing: error)
            }
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: data, as: UTF8.self)

        process.terminationHandler = nil
        return (status, output)
    }

    private func runSudoCommand(_ arguments: [String]) async throws -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: sudoPath)
        process.arguments = arguments

        var env = ProcessInfo.processInfo.environment
        env["SUDO_ASKPASS"] = askpassScriptPath
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        return try await runProcessAndCaptureOutput(process, pipe: pipe)
    }

    private func ensureAskpassScript() async throws {
        guard let executableURL = Bundle.main.executableURL else {
            throw NSError(domain: "VPNService", code: 910, userInfo: [
                NSLocalizedDescriptionKey: "Could not locate the administrator password prompt."
            ])
        }

        let script = NativeAdminPrompt.askpassScript(executablePath: executableURL.path)

        if !FileManager.default.fileExists(atPath: askpassScriptPath) {
            try script.write(toFile: askpassScriptPath, atomically: true, encoding: .utf8)

            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["700", askpassScriptPath]

            let pipe = Pipe()
            chmod.standardOutput = pipe
            chmod.standardError = pipe

            let result = try await runProcessAndCaptureOutput(chmod, pipe: pipe)

            if result.status != 0 {
                let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
                throw NSError(
                    domain: "VPNService",
                    code: 910,
                    userInfo: [
                        NSLocalizedDescriptionKey: output.isEmpty
                            ? "Failed to prepare sudo askpass helper."
                            : output
                    ]
                )
            }
        }
    }

    private func readTunnelPIDFromFile() -> Int32? {
        guard FileManager.default.fileExists(atPath: pidFilePath) else { return nil }

        do {
            let text = try String(contentsOfFile: pidFilePath, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)

            guard let pid = Int32(text), pid > 0 else { return nil }

            if tunnelPID != pid {
                tunnelPID = pid
                emitLog("Captured openconnect PID from pid-file: \(pid)")
            }

            return pid
        } catch {
            return nil
        }
    }

    private func findOpenconnectChildPID() async -> Int32? {
        guard let parentPID = process?.processIdentifier, parentPID > 0 else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: pgrepPath)
        process.arguments = ["-P", String(parentPID), "openconnect"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            let result = try await runProcessAndCaptureOutput(process, pipe: pipe)
            guard result.status == 0 else { return nil }

            let lines = result.output
                .split(whereSeparator: \.isNewline)
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }

            guard let first = lines.first, let pid = Int32(first), pid > 0 else { return nil }

            if tunnelPID != pid {
                tunnelPID = pid
                emitLog("Captured openconnect PID from child process lookup: \(pid)")
            }

            return pid
        } catch {
            return nil
        }
    }

    private func resolveTunnelPID(timeoutSeconds: TimeInterval = 3.0) async -> Int32? {
        let deadline = Date().addingTimeInterval(timeoutSeconds)

        while Date() < deadline {
            if let pid = readTunnelPIDFromFile() {
                return pid
            }

            if let pid = await findOpenconnectChildPID() {
                return pid
            }

            try? await Task.sleep(nanoseconds: 200_000_000)
        }

        return tunnelPID
    }

    private func waitForProcessExit(pid: Int32, timeoutSeconds: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeoutSeconds)

        while Date() < deadline {
            if kill(pid, 0) != 0 && errno == ESRCH {
                emitLog("Confirmed that PID \(pid) has exited.")
                return true
            }

            try? await Task.sleep(nanoseconds: 200_000_000)
        }

        return false
    }

    private func makePTY() throws -> (FileHandle, FileHandle) {
        var masterFD: Int32 = 0
        var slaveFD: Int32 = 0

        guard openpty(&masterFD, &slaveFD, nil, nil, nil) == 0 else {
            throw NSError(
                domain: "VPNService",
                code: 500,
                userInfo: [NSLocalizedDescriptionKey: "Failed to create PTY session."]
            )
        }

        let master = FileHandle(fileDescriptor: masterFD, closeOnDealloc: true)
        let slave = FileHandle(fileDescriptor: slaveFD, closeOnDealloc: true)
        return (master, slave)
    }

    private func resetSessionState() {
        fullOutput = ""
        bufferedChunk = ""
        hasSentPassword = false
        awaitingOTP = false
        disconnectRequested = false
        tunnelConnected = false
        tunnelPID = nil
    }

    private func handleIncomingText(_ text: String) {
        fullOutput += text
        bufferedChunk += text

        flushLogsIfPossible()

        let lower = text.lowercased()

        switch sessionMode {
        case .authenticating:
            if !hasSentPassword && lower.contains("password:") {
                hasSentPassword = true
                emitLog("Password prompt detected. Sending VPN password.")
                do {
                    try writeToSession(savedPassword + "\n")
                } catch {
                    emitError("Failed to send VPN password: \(error.localizedDescription)")
                }
            }

            if lower.contains("code:") && !awaitingOTP {
                awaitingOTP = true
                emitLog("OTP prompt detected. Waiting for OTP input.")
                DispatchQueue.main.async { [weak self] in
                    self?.onAwaitingOTP?()
                }
            }

        case .tunnel:
            if !tunnelConnected && (
                lower.contains("configured as ") ||
                lower.contains("established dtls connection") ||
                lower.contains("esp session established") ||
                lower.contains("session authentication will expire")
            ) {
                tunnelConnected = true
                emitLog("VPN tunnel appears established.")
                DispatchQueue.main.async { [weak self] in
                    self?.onConnected?()
                }
            }

        case .none:
            break
        }
    }

    private func flushLogsIfPossible() {
        let normalized = bufferedChunk.replacingOccurrences(of: "\r", with: "\n")
        let parts = normalized.components(separatedBy: "\n")

        for line in parts.dropLast() {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            guard shouldDisplayLogLine(trimmed) else { continue }
            emitLog(trimmed)
        }

        bufferedChunk = parts.last ?? ""
    }

    private func shouldDisplayLogLine(_ line: String) -> Bool {
        let suppressedPrefixes = [
            "route: writing to routing socket: File exists",
            "Unexpected pre-PPP packet header for encap 5.",
            "< 0000:",
            "< 0010:"
        ]

        if line.contains("COOKIE=") || line.contains("Set-Cookie:") { return false }
        if !savedPassword.isEmpty && line.contains(savedPassword) { return false }
        return !suppressedPrefixes.contains { line.hasPrefix($0) }
    }

    private func handleProcessTermination(status: Int32) {
        if !bufferedChunk.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let finalLine = bufferedChunk.trimmingCharacters(in: .whitespacesAndNewlines)
            if shouldDisplayLogLine(finalLine) {
                emitLog(finalLine)
            }
        }

        let finishedMode = sessionMode
        let outputSnapshot = fullOutput
        let passwordSnapshot = savedPassword
        let pendingDisconnectContinuation = disconnectContinuation
        let wasDisconnectRequested = disconnectRequested

        cleanupSession()

        if wasDisconnectRequested {
            disconnectRequested = false
            disconnectContinuation = nil
            emitLog("VPN session interrupted.")
            pendingDisconnectContinuation?.resume()

            DispatchQueue.main.async { [weak self] in
                self?.onDisconnected?()
            }
            return
        }

        if let pendingDisconnectContinuation {
            disconnectContinuation = nil
            pendingDisconnectContinuation.resume()
        }

        switch finishedMode {
        case .authenticating:
            if status == 0 {
                do {
                    let session = try parseAuthSession(from: outputSnapshot)
                    emitLog("Authentication completed successfully.")
                    DispatchQueue.main.async { [weak self] in
                        self?.onAuthenticated?(session)
                    }
                } catch {
                    emitError(error.localizedDescription)
                }
            } else {
                emitError(buildFailureMessage(exitCode: status, output: Self.redactedOutput(outputSnapshot, password: passwordSnapshot)))
            }

        case .tunnel:
            if status == 0 {
                emitLog("VPN tunnel process exited normally.")
                DispatchQueue.main.async { [weak self] in
                    self?.onDisconnected?()
                }
            } else {
                emitError(buildFailureMessage(exitCode: status, output: Self.redactedOutput(outputSnapshot, password: passwordSnapshot)))
            }

        case .none:
            if status != 0 {
                emitError(buildFailureMessage(exitCode: status, output: Self.redactedOutput(outputSnapshot, password: passwordSnapshot)))
            }
        }
    }

    private func buildFailureMessage(exitCode: Int32, output: String) -> String {
        let cleaned = output
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if !cleaned.isEmpty {
            return cleaned
        }

        return "VPN process exited with code \(exitCode)."
    }

    private func writeToSession(_ text: String) throws {
        guard let masterHandle else {
            throw NSError(
                domain: "VPNService",
                code: 104,
                userInfo: [NSLocalizedDescriptionKey: "No active PTY handle."]
            )
        }

        guard let data = text.data(using: .utf8) else {
            throw NSError(
                domain: "VPNService",
                code: 105,
                userInfo: [NSLocalizedDescriptionKey: "Failed to encode session input."]
            )
        }

        masterHandle.write(data)
    }

    private func cleanupSession() {
        masterHandle?.readabilityHandler = nil
        masterHandle?.closeFile()
        masterHandle = nil

        process?.terminationHandler = nil
        process = nil

        sessionMode = nil
        hasSentPassword = false
        awaitingOTP = false
        savedPassword = ""
        bufferedChunk = ""
        tunnelConnected = false
        tunnelPID = nil
        disconnectContinuation = nil

        try? FileManager.default.removeItem(atPath: pidFilePath)
    }

    private func parseAuthSession(from output: String) throws -> VPNAuthSession {
        let values = parseShellAssignments(output)

        guard
            let cookie = values["COOKIE"],
            let connectURL = values["CONNECT_URL"],
            let fingerprint = values["FINGERPRINT"]
        else {
            throw NSError(
                domain: "VPNService",
                code: 1001,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        """
                        Authentication completed but required auth values were not found.
                        Parsed keys: \(values.keys.sorted().joined(separator: ", "))
                        """
                ]
            )
        }

        return VPNAuthSession(
            cookie: cookie,
            connectURL: connectURL,
            fingerprint: fingerprint,
            resolve: values["RESOLVE"]
        )
    }

    private func parseShellAssignments(_ text: String) -> [String: String] {
        var result: [String: String] = [:]

        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")

        let lines = normalized.components(separatedBy: "\n")

        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else { continue }

            if let range = line.range(of: #"^([A-Z_]+)='(.*)'$"#, options: .regularExpression) {
                let matched = String(line[range])

                if let eqIndex = matched.firstIndex(of: "=") {
                    let key = String(matched[..<eqIndex])
                    var value = String(matched[matched.index(after: eqIndex)...])

                    if value.hasPrefix("'"), value.hasSuffix("'"), value.count >= 2 {
                        value.removeFirst()
                        value.removeLast()
                    }

                    result[key] = value
                    continue
                }
            }

            if let eqIndex = line.firstIndex(of: "=") {
                let key = String(line[..<eqIndex]).trimmingCharacters(in: .whitespacesAndNewlines)
                var value = String(line[line.index(after: eqIndex)...]).trimmingCharacters(in: .whitespacesAndNewlines)

                guard !key.isEmpty else { continue }

                if value.hasPrefix("'"), value.hasSuffix("'"), value.count >= 2 {
                    value.removeFirst()
                    value.removeLast()
                }

                result[key] = value
            }
        }

        return result
    }

    private static func redactedOutput(_ output: String, password: String) -> String {
        var result = output
        if !password.isEmpty { result = result.replacingOccurrences(of: password, with: "[redacted]") }
        return result.components(separatedBy: .newlines).filter {
            !$0.localizedCaseInsensitiveContains("cookie")
        }.joined(separator: "\n")
    }

    private func emitLog(_ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        DispatchQueue.main.async { [weak self] in
            self?.onLog?(trimmed)
        }
    }

    private func emitError(_ message: String) {
        DispatchQueue.main.async { [weak self] in
            self?.onError?(message)
        }
    }
}
