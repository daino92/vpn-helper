import Foundation
import Darwin

nonisolated enum HelperPolicy {
    static func validateSession(cookie: String, connectURL: String, fingerprint: String, resolve: String?) throws {
        guard !cookie.isEmpty, cookie.utf8.count <= 65536,
              !cookie.contains(where: { $0.isNewline || $0 == "\0" }),
              let url = URLComponents(string: connectURL),
              url.scheme == "https", url.host?.lowercased() == "vpnaccess.ote.gr",
              url.port == nil || url.port == 443,
              url.user == nil, url.password == nil, url.fragment == nil,
              connectURL.utf8.count < 2048,
              !connectURL.contains(where: { $0.isNewline || $0 == "\0" }) else {
            throw HelperFailure(message: "The helper rejected an invalid VPN session or server address.")
        }
        guard validFingerprint(fingerprint) else {
            throw HelperFailure(message: "The helper rejected an invalid server certificate fingerprint.")
        }
        if let resolve, resolve != "vpnaccess.ote.gr:195.167.99.229" {
            throw HelperFailure(message: "The helper rejected an unexpected VPN DNS override.")
        }
    }

    private static func validFingerprint(_ fingerprint: String) -> Bool {
        guard fingerprint.utf8.count <= 128 else { return false }
        if fingerprint.hasPrefix("pin-sha256:") {
            let encoded = String(fingerprint.dropFirst("pin-sha256:".count))
            return Data(base64Encoded: encoded)?.count == 32
        }
        if fingerprint.hasPrefix("sha256:") {
            let digest = fingerprint.dropFirst("sha256:".count).filter { $0 != ":" }
            return digest.count == 64 && digest.allSatisfy { $0.isASCII && $0.isHexDigit }
        }
        return false
    }

    /// A persistent root service must never execute the user's writable Homebrew
    /// installation. Deployment supplies a relocated, root-managed toolchain.
    static func validateManagedTool(_ path: String) throws {
        let root = HelperConstants.toolDirectory
        guard path == root + "/openconnect" || path == root + "/vpn-slice" else {
            throw HelperFailure(message: "The helper rejected an unapproved executable.")
        }
        var current = URL(fileURLWithPath: path)
        while current.path != "/" {
            let attributes = try FileManager.default.attributesOfItem(atPath: current.path)
            let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            guard (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == 0,
                  permissions & 0o022 == 0,
                  attributes[.type] as? FileAttributeType != .typeSymbolicLink else {
                throw HelperFailure(message: "The helper's VPN tools must be root-owned, must not use symbolic links, and must not be writable by other users.")
            }
            current.deleteLastPathComponent()
        }
        guard FileManager.default.isExecutableFile(atPath: path) else {
            throw HelperFailure(message: "The managed VPN tool is not executable.")
        }
        try HelperSecurity.validateManagedExecutable(at: path)
    }

    static func validateToolDirectory() throws {
        guard let entries = FileManager.default.enumerator(atPath: HelperConstants.toolDirectory) else {
            throw HelperFailure(message: "The managed VPN toolchain is missing.")
        }
        for case let relativePath as String in entries {
            let path = HelperConstants.toolDirectory + "/" + relativePath
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            let type = attributes[.type] as? FileAttributeType
            let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            guard (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == 0,
                  permissions & 0o022 == 0,
                  type == .typeRegular || type == .typeDirectory else {
                throw HelperFailure(message: "Every toolchain file must be root-owned and protected from modification by other users; symbolic links are not allowed.")
            }
        }
    }
}
