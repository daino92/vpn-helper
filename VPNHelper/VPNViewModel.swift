//
//  VPNViewModel.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import Foundation
import SwiftUI
import Combine

@MainActor
final class VPNViewModel: ObservableObject {
    @AppStorage("savedEmailPrefix") var savedEmailPrefix: String = ""
    @AppStorage("rememberEmailPrefix") var rememberEmailPrefix: Bool = false

    @Published var emailPrefix: String = ""
    @Published var vpnPassword: String = ""
    @Published var otp: String = ""

    @Published var connectionState: VPNConnectionState = .disconnected
    @Published var adminAccessState: AdminAccessState = .locked
    @Published var logs: [VPNLogEntry] = []
    @Published var isBusy: Bool = false
    @Published var errorMessage: String?
    @Published var authSession: VPNAuthSession?

    @Published var rememberCredentials = false
    private var didLoadCredentials = false
    private let credentialStore: any CredentialStore
    private let service: VPNServiceProtocol

    let emailDomain = "@groupnet.gr"

    init(service: VPNServiceProtocol, credentialStore: (any CredentialStore)? = nil, userDefaults: UserDefaults = .standard) {
        _savedEmailPrefix = AppStorage(wrappedValue: "", "savedEmailPrefix", store: userDefaults)
        _rememberEmailPrefix = AppStorage(wrappedValue: false, "rememberEmailPrefix", store: userDefaults)
        self.credentialStore = credentialStore ?? KeychainCredentialStore()
        self.service = service
        bindServiceCallbacks()
    }

    var fullEmail: String {
        let trimmed = emailPrefix.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        return trimmed + emailDomain
    }

    var canStartLogin: Bool {
        !emailPrefix.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !vpnPassword.isEmpty &&
        !isBusy &&
        (connectionState == .disconnected || connectionState == .error)
    }

    var canSubmitOTP: Bool {
        otp.count == 6 && otp.allSatisfy { $0.isASCII && $0.isNumber } &&
        !isBusy &&
        connectionState == .awaitingOTP
    }

    var canDisconnect: Bool {
        !isBusy && (
            connectionState == .authenticated ||
            connectionState == .connecting ||
            connectionState == .connected ||
            connectionState == .authenticating ||
            connectionState == .awaitingOTP
        )
    }

    var canFixNetwork: Bool {
        !isBusy
    }

    func onAppear() {
        guard !didLoadCredentials else { return }
        didLoadCredentials = true
        if rememberEmailPrefix { emailPrefix = savedEmailPrefix }
        do {
            if let credentials = try credentialStore.load() {
                emailPrefix = credentials.emailPrefix
                vpnPassword = credentials.password
                rememberCredentials = true
            }
        } catch {
            errorMessage = "Could not read saved login: \(error.localizedDescription)"
        }
    }

    func setRememberCredentials(_ enabled: Bool) {
        do {
            if enabled {
                try saveCredentials()
            } else {
                try credentialStore.delete()
            }
            rememberCredentials = enabled
        } catch {
            errorMessage = "Could not update saved login: \(error.localizedDescription)"
        }
    }

    private func saveCredentials() throws {
        try credentialStore.save(SavedCredentials(
            emailPrefix: emailPrefix.trimmingCharacters(in: .whitespacesAndNewlines),
            password: vpnPassword
        ))
    }

    func toggleRememberEmail(_ enabled: Bool) {
        rememberEmailPrefix = enabled
        if enabled {
            savedEmailPrefix = emailPrefix.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            savedEmailPrefix = ""
        }
    }

    func persistEmailIfNeeded() {
        if rememberEmailPrefix {
            savedEmailPrefix = emailPrefix.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    func sanitizeOTPInput() {
        let digitsOnly = otp.filter { $0.isASCII && $0.isNumber }
        let limited = String(digitsOnly.prefix(6))

        if otp != limited {
            otp = limited
        }
    }

    func requestAdminAccess() async {
        errorMessage = nil
        adminAccessState = .unlocking
        isBusy = true
        addLog("Requesting administrator privileges from macOS...")

        do {
            try await service.requestAdminAccess()
            adminAccessState = .unlocked
            addLog("Admin access granted.")
        } catch {
            adminAccessState = .error
            errorMessage = error.localizedDescription
            addLog("Admin access failed: \(error.localizedDescription)")
        }

        isBusy = false
    }

    func startLogin() async {
        guard canStartLogin else { return }
        if rememberCredentials {
            do {
                try saveCredentials()
            } catch {
                errorMessage = "Could not save login: \(error.localizedDescription)"
                return
            }
        }
        errorMessage = nil
        authSession = nil
        otp = ""
        persistEmailIfNeeded()

        connectionState = .authenticating
        isBusy = true
        addLog("Starting VPN login for \(fullEmail)...")

        do {
            try await service.startLogin(email: fullEmail, password: vpnPassword)
            isBusy = false
        } catch {
            connectionState = .error
            errorMessage = error.localizedDescription
            addLog("Start login failed: \(error.localizedDescription)")
            isBusy = false
        }
    }

    func submitOTP() async {
        guard canSubmitOTP else { return }
        errorMessage = nil
        isBusy = true
        addLog("Submitting OTP and waiting for authenticated session...")

        do {
            try await service.submitOTP(otp.trimmingCharacters(in: .whitespacesAndNewlines))
            addLog("OTP submitted to the active VPN session.")
            if connectionState == .awaitingOTP {
                connectionState = .authenticating
            }
            isBusy = false
        } catch {
            connectionState = .error
            errorMessage = error.localizedDescription
            addLog("OTP submission failed: \(error.localizedDescription)")
            isBusy = false
        }
    }

    func establishTunnel() async {
        guard let authSession else { return }

        errorMessage = nil
        isBusy = true
        connectionState = .connecting
        addLog("Starting privileged VPN tunnel using authenticated session...")

        do {
            try await service.startTunnel(using: authSession)
            isBusy = false
        } catch {
            connectionState = .error
            errorMessage = error.localizedDescription
            addLog("Tunnel start failed: \(error.localizedDescription)")
            isBusy = false
        }
    }

    func disconnect() async {
        errorMessage = nil
        connectionState = .disconnecting
        isBusy = true
        addLog("Disconnecting...")

        do {
            try await service.disconnect()
        } catch {
            connectionState = .error
            errorMessage = error.localizedDescription
            addLog("Disconnect failed: \(error.localizedDescription)")
            isBusy = false
        }
    }

    func fixNetwork() async {
        errorMessage = nil
        isBusy = true
        addLog("Running network fix...")

        do {
            let result = try await service.fixNetwork()
            for line in result {
                addLog(line)
            }
            addLog("Network fix completed.")
        } catch {
            errorMessage = error.localizedDescription
            addLog("Network fix failed: \(error.localizedDescription)")
        }

        isBusy = false
    }

    func addLog(_ message: String) {
        logs.append(VPNLogEntry(timestamp: Date(), message: message))
        if logs.count > 1000 {
            logs.removeFirst(logs.count - 1000)
        }
    }

    private func bindServiceCallbacks() {
        service.onLog = { [weak self] message in
            guard let self else { return }
            self.addLog(message)
        }

        service.onAwaitingOTP = { [weak self] in
            guard let self else { return }
            self.connectionState = .awaitingOTP
            self.isBusy = false
            self.addLog("OTP should arrive on your phone. Enter it and press Submit OTP.")
        }

        service.onAuthenticated = { [weak self] session in
            guard let self else { return }
            self.authSession = session
            self.connectionState = .authenticated
            self.isBusy = false
            self.addLog("Authentication succeeded.")
            self.addLog("COOKIE received.")
            self.addLog("CONNECT_URL: \(session.connectURL)")
            self.addLog("FINGERPRINT: \(session.fingerprint)")
            if let resolve = session.resolve {
                self.addLog("RESOLVE: \(resolve)")
            }
            self.addLog("Authenticated session is ready. Starting VPN tunnel automatically...")

            Task {
                await self.establishTunnel()
            }
        }

        service.onConnected = { [weak self] in
            guard let self else { return }
            self.connectionState = .connected
            self.isBusy = false
            self.addLog("VPN tunnel established.")
        }

        service.onDisconnected = { [weak self] in
            guard let self else { return }
            self.authSession = nil
            self.otp = ""
            self.connectionState = .disconnected
            self.isBusy = false
            self.addLog("Disconnected.")
        }

        service.onError = { [weak self] message in
            guard let self else { return }
            self.connectionState = .error
            self.isBusy = false
            self.errorMessage = message
            self.addLog("VPN session failed: \(message)")
        }
    }
}
