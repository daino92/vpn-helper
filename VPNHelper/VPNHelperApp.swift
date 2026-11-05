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
        if CommandLine.arguments.contains("--sudo-askpass") {
            NativeAdminPrompt.run()
        } else {
            VPNHelperApp.main()
        }
    }
}

struct VPNHelperApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var viewModel = VPNViewModel(service: VPNService())

    var body: some Scene {
        Window("VPN Helper", id: "main") {
            if isRunningTests {
                // Hosted unit tests must not read the user's real Keychain.
                Color.clear.frame(width: 1, height: 1)
            } else {
                ContentView(viewModel: viewModel)
                    .background(VPNWindowRegistration { window in
                        appDelegate.register(window: window, model: viewModel)
                    })
            }
        }
        .windowResizability(.contentSize)
    }

    private var isRunningTests: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["XCTestConfigurationFilePath"] != nil || environment["XCTestBundlePath"] != nil
    }
}
