import Foundation
import Security

nonisolated enum HelperSecurity {
    static func signingRequirement() throws -> String {
        let identity = try currentIdentity()
        return "anchor apple generic and identifier \"\(HelperConstants.identifier)\" and certificate leaf[subject.OU] = \"\(identity.team)\" and cdhash H\"\(identity.hash)\""
    }

    static func validateManagedExecutable(at path: String) throws {
        let identity = try currentIdentity()
        let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? file.close() }
        let header = try file.read(upToCount: 4) ?? Data()
        let machOMagic: [Data] = [
            Data([0xcf, 0xfa, 0xed, 0xfe]), Data([0xfe, 0xed, 0xfa, 0xcf]),
            Data([0xca, 0xfe, 0xba, 0xbe]), Data([0xbe, 0xba, 0xfe, 0xca]),
            Data([0xca, 0xfe, 0xba, 0xbf]), Data([0xbf, 0xba, 0xfe, 0xca])
        ]
        guard machOMagic.contains(header) else {
            throw HelperFailure(message: "The managed VPN tools must be standalone Mach-O executables; script launchers are not accepted.")
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            throw HelperFailure(message: "The managed VPN tools must be signed standalone executables, not Homebrew scripts.")
        }
        let info = try signingInformation(code)
        _ = try validateIdentity(info)
        let text = "anchor apple generic and identifier \"\(HelperConstants.identifier).\(URL(fileURLWithPath: path).lastPathComponent)\" and certificate leaf[subject.OU] = \"\(identity.team)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else {
            throw HelperFailure(message: "The VPN tools must be signed with the same Apple Developer team as VPN Helper.")
        }
    }

    private static func currentIdentity() throws -> (team: String, hash: String) {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            throw HelperFailure(message: "Could not verify this app's signature.")
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw HelperFailure(message: "Could not inspect the signed executable.")
        }
        return try validateIdentity(signingInformation(staticCode))
    }

    private static func signingInformation(_ code: SecStaticCode) throws -> [String: Any] {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any] else {
            throw HelperFailure(message: "Could not read code signing information.")
        }
        return info
    }

    static func validateIdentity(_ info: [String: Any]) throws -> (team: String, hash: String) {
        guard let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              team.count == 10, team.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
              let flags = info[kSecCodeInfoFlags as String] as? UInt32,
              flags & 0x10000 != 0, flags & 0x2 == 0 else {
            throw HelperFailure(message: "Touch ID setup requires a Release build signed with an Apple Developer certificate and Hardened Runtime. This build uses local ad-hoc signing. You can continue connecting with your Mac password.")
        }
        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let prohibited = [
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-executable-page-protection",
            "com.apple.security.cs.allow-jit"
        ]
        guard !prohibited.contains(where: { entitlements[$0] as? Bool == true }) else {
            throw HelperFailure(message: "The privileged helper requires a hardened, non-debuggable build with library validation enabled.")
        }
        guard let hash = info[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else {
            throw HelperFailure(message: "Could not read the signed build identity.")
        }
        return (team, hash.map { String(format: "%02x", $0) }.joined())
    }
}
