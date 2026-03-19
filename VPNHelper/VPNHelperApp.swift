//
//  VPNHelperApp.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import SwiftUI

@main
struct VPNHelperApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: VPNViewModel(service: VPNService()))
        }
        .windowResizability(.contentSize)
    }
}
