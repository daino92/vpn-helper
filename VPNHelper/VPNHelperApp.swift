//
//  VPNHelperApp.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import SwiftUI
import AppKit

@main
@MainActor
enum VPNHelperEntryPoint {
    static func main() {
        if CommandLine.arguments.contains("--privileged-helper") {
            PrivilegedDaemon.run()
        } else if CommandLine.arguments.contains("--sudo-askpass") {
            NativeAdminPrompt.run()
        } else {
            VPNHelperApp.main()
        }
    }
}

struct VPNHelperApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            if isRunningTests {
                // Hosted unit tests must not read the user's real Keychain.
                Color.clear.frame(width: 1, height: 1)
            } else {
                ContentView(viewModel: VPNViewModel(service: VPNService()))
            }
        }
        .windowResizability(.contentSize)
    }

    private var isRunningTests: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["XCTestConfigurationFilePath"] != nil || environment["XCTestBundlePath"] != nil
    }
}
