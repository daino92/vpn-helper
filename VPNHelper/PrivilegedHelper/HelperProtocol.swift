import Foundation

@objc nonisolated protocol VPNPrivilegedHelperProtocol {
    func ping(reply: @escaping ([String], String?) -> Void)
    func startTunnel(cookie: String, connectURL: String, fingerprint: String, resolve: String?, reply: @escaping ([String], String?) -> Void)
    func stopTunnel(reply: @escaping ([String], String?) -> Void)
    func repairNetwork(reply: @escaping ([String], String?) -> Void)
}

@objc nonisolated protocol VPNPrivilegedClientProtocol {
    func tunnelOutput(_ data: Data)
    func tunnelExited(_ status: Int32)
}

nonisolated enum HelperConstants {
    static let identifier = "com.dainocorp.VPNHelper"
    static let machService = "com.dainocorp.VPNHelper.privileged"
    static let plistName = machService + ".plist"
    static let protocolVersion = "1"
    static let toolDirectory = "/Library/PrivilegedHelperTools/com.dainocorp.VPNHelper.tools"
}

nonisolated struct HelperFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
