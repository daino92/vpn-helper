import Foundation
import Security
import Testing
@testable import VPNHelper

@MainActor
struct PrivilegedHelperTests {
    private let fingerprint = "pin-sha256:" + Data(repeating: 1, count: 32).base64EncodedString()

    @Test func acceptsExpectedVPNSession() throws {
        try HelperPolicy.validateSession(cookie: "session-cookie", connectURL: "https://vpnaccess.ote.gr/", fingerprint: fingerprint, resolve: "vpnaccess.ote.gr:195.167.99.229")
    }

    @Test(arguments: ["https://attacker.example/", "file:///etc/passwd", "https://vpnaccess.ote.gr.attacker.example/", "http://vpnaccess.ote.gr/", "https://user:pass@vpnaccess.ote.gr/", "https://vpnaccess.ote.gr:8443/"])
    func rejectsUnexpectedServer(_ server: String) {
        #expect(throws: HelperFailure.self) {
            try HelperPolicy.validateSession(cookie: "cookie", connectURL: server, fingerprint: fingerprint, resolve: nil)
        }
    }

    @Test func rejectsInjectedCookieAndDNSOverride() {
        #expect(throws: HelperFailure.self) {
            try HelperPolicy.validateSession(cookie: "cookie\n--script=/tmp/evil", connectURL: "https://vpnaccess.ote.gr/", fingerprint: fingerprint, resolve: nil)
        }
        #expect(throws: HelperFailure.self) {
            try HelperPolicy.validateSession(cookie: "cookie", connectURL: "https://vpnaccess.ote.gr/", fingerprint: fingerprint, resolve: "vpnaccess.ote.gr:127.0.0.1")
        }
    }

    @Test(arguments: ["", "pin-sha256:", "pin-sha256:not-a-valid-pin", "sha256:1234", "--script=/tmp/evil"])
    func rejectsInvalidFingerprint(_ pin: String) {
        #expect(throws: HelperFailure.self) {
            try HelperPolicy.validateSession(cookie: "cookie", connectURL: "https://vpnaccess.ote.gr/", fingerprint: pin, resolve: nil)
        }
    }

    @Test func refusesHomebrewExecutables() {
        #expect(throws: HelperFailure.self) { try HelperPolicy.validateManagedTool("/opt/homebrew/bin/openconnect") }
        #expect(throws: HelperFailure.self) { try HelperPolicy.validateManagedTool("/tmp/openconnect") }
    }

    @Test func rejectsAdHocAndDebuggableSignatures() {
        var info: [String: Any] = [
            kSecCodeInfoTeamIdentifier as String: "ABCDEFGHIJ",
            kSecCodeInfoFlags as String: UInt32(0x10000),
            kSecCodeInfoUnique as String: Data(repeating: 1, count: 20)
        ]
        info[kSecCodeInfoFlags as String] = UInt32(0x10002)
        #expect(throws: HelperFailure.self) { try HelperSecurity.validateIdentity(info) }
        info[kSecCodeInfoFlags as String] = UInt32(0x10000)
        info[kSecCodeInfoEntitlementsDict as String] = ["com.apple.security.get-task-allow": true]
        #expect(throws: HelperFailure.self) { try HelperSecurity.validateIdentity(info) }
        info[kSecCodeInfoEntitlementsDict as String] = ["com.apple.security.cs.disable-library-validation": true]
        #expect(throws: HelperFailure.self) { try HelperSecurity.validateIdentity(info) }
    }

    @Test func cancelledAuthenticationNeverRunsPrivilegedOperation() async {
        var operationWasCalled = false
        do {
            try await TestAuthenticator(shouldFail: true).authorize(reason: "Test") {
                operationWasCalled = true
            }
            Issue.record("Cancelled authentication should throw.")
        } catch {
            #expect(!operationWasCalled)
        }
    }

    @Test func successfulAuthenticationRunsOperation() async throws {
        let result = try await TestAuthenticator(shouldFail: false).authorize(reason: "Test") { 42 }
        #expect(result == 42)
    }
}

private struct TestAuthenticator: DeviceOwnerAuthenticating {
    let shouldFail: Bool
    func authenticate(reason: String) async throws {
        if shouldFail { throw HelperFailure(message: "Cancelled") }
    }
}
