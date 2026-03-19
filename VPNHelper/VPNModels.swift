//
//  VPNModels.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import Foundation

enum VPNConnectionState: String {
    case disconnected
    case authenticating
    case awaitingOTP
    case authenticated
    case connecting
    case connected
    case disconnecting
    case error
}

enum AdminAccessState: String {
    case locked
    case unlocking
    case unlocked
    case error
}

struct VPNLogEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: Date
    let message: String
}

struct VPNAuthSession: Equatable {
    let cookie: String
    let connectURL: String
    let fingerprint: String
    let resolve: String?
}
