//
//  MockVPNService.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import Foundation

final class MockVPNService: VPNServiceProtocol {
    var onLog: ((String) -> Void)?
    var onAwaitingOTP: (() -> Void)?
    var onAuthenticated: ((VPNAuthSession) -> Void)?
    var onConnected: (() -> Void)?
    var onDisconnected: (() -> Void)?
    var onError: ((String) -> Void)?

    var helperInstallationState: HelperInstallationState { .notInstalled }
    var usesPrivilegedHelper: Bool { false }
    func setUpPrivilegedHelper() async throws {}
    func usePasswordAuthentication() {}

    func startLogin(email: String, password: String) async throws {
        onLog?("Preview mode start login for \(email)")
        onLog?("Preview mode password accepted")
        onAwaitingOTP?()
    }

    func submitOTP(_ otp: String) async throws {
        onLog?("Preview mode OTP submit: \(otp)")
        onAuthenticated?(
            VPNAuthSession(
                cookie: "preview-cookie",
                connectURL: "https://preview.local",
                fingerprint: "preview-fingerprint",
                resolve: nil
            )
        )
    }

    func startTunnel(using session: VPNAuthSession) async throws {
        onLog?("Preview mode tunnel start using cookie")
        onConnected?()
    }

    func disconnect() async throws {
        onDisconnected?()
    }

    func fixNetwork() async throws -> [String] {
        ["Preview mode fix network"]
    }
}
