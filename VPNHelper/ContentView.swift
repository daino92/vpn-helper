//
//  ContentView.swift
//  VPNHelper
//
//  Created by Dionysis Kalepanagos on 15/3/26.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var viewModel: VPNViewModel
    @State private var showVPNPassword = false

    init(viewModel: VPNViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            headerSection
            credentialsSection
            actionsSection
            logSection
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 680)
        .onAppear {
            viewModel.onAppear()
        }
    }
}

private extension ContentView {
    var headerSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("VPN Helper")
                .font(.title2)
                .bold()

            HStack(spacing: 10) {
                Button {
                    Task {
                        await viewModel.requestAdminAccess()
                    }
                } label: {
                    Image(systemName: lockIconName)
                        .foregroundStyle(lockColor)
                        .font(.title3)
                }
                .buttonStyle(.plain)
                .disabled(viewModel.isBusy || viewModel.adminAccessState == .unlocked)

                Text("Admin Access: \(viewModel.adminAccessState.rawValue.capitalized)")
                    .font(.subheadline)

                Spacer()
            }

            Text("Connection State: \(readableConnectionState)")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            if let errorMessage = viewModel.errorMessage, !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
    }

    var credentialsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Credentials")
                .font(.headline)

            VStack(alignment: .leading, spacing: 6) {
                Text("Email")
                    .font(.subheadline)

                HStack(spacing: 8) {
                    TextField("username", text: $viewModel.emailPrefix)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .onChange(of: viewModel.emailPrefix) { _, _ in
                            viewModel.persistEmailIfNeeded()
                        }

                    Text(viewModel.emailDomain)
                        .foregroundStyle(.secondary)
                }
            }

            Toggle("Remember email", isOn: Binding(
                get: { viewModel.rememberEmailPrefix },
                set: { viewModel.toggleRememberEmail($0) }
            ))

            VStack(alignment: .leading, spacing: 6) {
                Text("VPN Password")
                    .font(.subheadline)

                HStack(spacing: 6) {
                    Group {
                        if showVPNPassword {
                            TextField("Enter VPN password", text: $viewModel.vpnPassword)
                        } else {
                            SecureField("Enter VPN password", text: $viewModel.vpnPassword)
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)

                    Button {
                        showVPNPassword.toggle()
                    } label: {
                        Image(systemName: showVPNPassword ? "eye.slash" : "eye")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("OTP")
                    .font(.subheadline)

                TextField("123456", text: $viewModel.otp)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .frame(width: 78)
                    .disabled(viewModel.connectionState != .awaitingOTP || viewModel.isBusy)
                    .onChange(of: viewModel.otp) { _, _ in
                        viewModel.sanitizeOTPInput()
                    }
            }
        }
    }

    var actionsSection: some View {
        HStack(spacing: 12) {
            Button("Start VPN Login") {
                Task {
                    await viewModel.startLogin()
                }
            }
            .disabled(!viewModel.canStartLogin)

            Button("Submit OTP") {
                Task {
                    await viewModel.submitOTP()
                }
            }
            .disabled(!viewModel.canSubmitOTP)

            Button("Disconnect VPN") {
                Task {
                    await viewModel.disconnect()
                }
            }
            .disabled(!viewModel.canDisconnect)

            Button("Fix Network") {
                Task {
                    await viewModel.fixNetwork()
                }
            }
            .disabled(!viewModel.canFixNetwork)

            if viewModel.isBusy {
                ProgressView()
                    .controlSize(.small)
                    .padding(.leading, 6)
            }

            Spacer()
        }
    }

    var logSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Connection Log")
                    .font(.headline)

                Spacer()

                Button("Copy Logs") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(formattedLogs, forType: .string)
                }
                .disabled(viewModel.logs.isEmpty)
            }

            TextEditor(text: .constant(formattedLogs))
                .font(.system(.body, design: .monospaced))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(8)
                .background(Color.gray.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    var formattedLogs: String {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium

        return viewModel.logs
            .map { entry in
                "[\(formatter.string(from: entry.timestamp))] \(entry.message)"
            }
            .joined(separator: "\n")
    }

    var readableConnectionState: String {
        switch viewModel.connectionState {
        case .disconnected: return "Disconnected"
        case .authenticating: return "Authenticating"
        case .awaitingOTP: return "Awaiting OTP"
        case .authenticated: return "Authenticated"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting"
        case .error: return "Error"
        }
    }

    var lockIconName: String {
        switch viewModel.adminAccessState {
        case .locked, .error:
            return "lock.fill"
        case .unlocking:
            return "lock.rotation"
        case .unlocked:
            return "lock.open.fill"
        }
    }

    var lockColor: Color {
        switch viewModel.adminAccessState {
        case .locked:
            return .orange
        case .unlocking:
            return .blue
        case .unlocked:
            return .green
        case .error:
            return .red
        }
    }
}

#Preview {
    ContentView(viewModel: VPNViewModel(service: MockVPNService()))
}
