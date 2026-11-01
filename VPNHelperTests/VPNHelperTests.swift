import AppKit
import Foundation
import Testing
@testable import VPNHelper

@MainActor
struct VPNHelperTests {
    private func isolatedDefaults() -> UserDefaults {
        UserDefaults(suiteName: "VPNHelperTests.\(UUID().uuidString)")!
    }

    @Test func systemAppearanceClearsDarkAndLightOverrides() {
        let application = NSApplication.shared
        let originalAppearance = application.appearance
        defer { application.appearance = originalAppearance }

        AppAppearance.dark.apply(to: application)
        #expect(application.appearance?.name == .darkAqua)
        AppAppearance.system.apply(to: application)
        #expect(application.appearance == nil)

        AppAppearance.light.apply(to: application)
        #expect(application.appearance?.name == .aqua)
        AppAppearance.system.apply(to: application)
        #expect(application.appearance == nil)
    }

    @Test func askpassScriptQuotesExecutablePath() {
        let script = NativeAdminPrompt.askpassScript(executablePath: "/Applications/Dionysis' VPN.app/Contents/MacOS/VPNHelper")
        #expect(script == "#!/bin/sh\nexec '/Applications/Dionysis'\\'' VPN.app/Contents/MacOS/VPNHelper' --sudo-askpass\n")
        #expect(!script.contains("osascript"))
    }

    @Test func savedLoginIsRestoredWithoutAdminUnlock() {
        let store = MemoryCredentialStore()
        store.credentials = SavedCredentials(emailPrefix: "tester", password: "secret")
        let model = VPNViewModel(service: MockVPNService(), credentialStore: store, userDefaults: isolatedDefaults())
        model.onAppear()
        #expect(model.fullEmail == "tester@groupnet.gr")
        #expect(model.vpnPassword == "secret")
        #expect(model.rememberCredentials)
        #expect(model.canStartLogin)
    }

    @Test func disablingSavedLoginRemovesKeychainEntry() {
        let store = MemoryCredentialStore()
        store.credentials = SavedCredentials(emailPrefix: "tester", password: "secret")
        let model = VPNViewModel(service: MockVPNService(), credentialStore: store, userDefaults: isolatedDefaults())
        model.onAppear()
        model.setRememberCredentials(false)
        #expect(store.credentials == nil)
        #expect(!model.rememberCredentials)
    }

    @Test func keychainFailureIsVisible() {
        let store = MemoryCredentialStore()
        store.shouldFail = true
        let model = VPNViewModel(service: MockVPNService(), credentialStore: store, userDefaults: isolatedDefaults())
        model.setRememberCredentials(true)
        #expect(!model.rememberCredentials)
        #expect(model.errorMessage != nil)
    }

    @Test func loginAdvancesToOTPWithoutAdminPreflight() async {
        let model = VPNViewModel(service: MockVPNService(), credentialStore: MemoryCredentialStore(), userDefaults: isolatedDefaults())
        model.emailPrefix = "tester"
        model.vpnPassword = "secret"
        await model.startLogin()
        #expect(model.connectionState == .awaitingOTP)
        model.otp = "123456"
        #expect(model.canSubmitOTP)
        await model.submitOTP()
        await Task.yield()
        #expect(model.connectionState == .connected || model.connectionState == .connecting || model.connectionState == .authenticated)
    }

    @Test func invalidOTPIsFilteredAndCannotBeSubmitted() {
        let model = VPNViewModel(service: MockVPNService(), credentialStore: MemoryCredentialStore(), userDefaults: isolatedDefaults())
        model.connectionState = .awaitingOTP
        model.otp = "12x34"
        model.sanitizeOTPInput()
        #expect(model.otp == "1234")
        #expect(!model.canSubmitOTP)
    }
}

private final class MemoryCredentialStore: CredentialStore {
    var credentials: SavedCredentials?
    var shouldFail = false
    enum Failure: Error { case unavailable }

    func load() throws -> SavedCredentials? { credentials }
    func save(_ credentials: SavedCredentials) throws {
        if shouldFail { throw Failure.unavailable }
        self.credentials = credentials
    }
    func delete() throws { credentials = nil }
}
