//
//  VPNServiceProtocol.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import Foundation

protocol VPNServiceProtocol: AnyObject {
    var onLog: ((String) -> Void)? { get set }
    var onAwaitingOTP: (() -> Void)? { get set }
    var onAuthenticated: ((VPNAuthSession) -> Void)? { get set }
    var onConnected: (() -> Void)? { get set }
    var onDisconnected: (() -> Void)? { get set }
    var onError: ((String) -> Void)? { get set }

    var helperInstallationState: HelperInstallationState { get }
    var usesPrivilegedHelper: Bool { get }
    func setUpPrivilegedHelper() async throws
    func usePasswordAuthentication()
    func startLogin(email: String, password: String) async throws
    func submitOTP(_ otp: String) async throws
    func startTunnel(using session: VPNAuthSession) async throws
    func disconnect() async throws
    func fixNetwork() async throws -> [String]
}
