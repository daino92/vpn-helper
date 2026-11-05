import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var viewModel: VPNViewModel
    @State private var showVPNPassword = false
    @AppStorage("showConnectionLogs") private var showLogs = false
    @AppStorage("appearance") private var appearance: AppAppearance = .system
    @State private var editLogin = false

    init(viewModel: VPNViewModel) {
        _viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            header
            Divider()
            if !viewModel.rememberCredentials || editLogin {
                credentials
            } else {
                HStack {
                    Label(viewModel.fullEmail, systemImage: "person.crop.circle")
                    Spacer()
                    Button("Edit login") { editLogin = true }
                        .buttonStyle(.borderless)
                        .foregroundStyle(AppTheme.magenta)
                }
                .padding(14)
                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
            }
            connectionControls
            if let error = viewModel.errorMessage, !error.isEmpty {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(AppTheme.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            Divider()
            diagnostics
        }
        .font(AppTheme.body)
        .tint(AppTheme.magenta)
        .padding(28)
        .frame(width: 460)
        .onAppear {
            appearance.apply(to: NSApplication.shared)
            viewModel.onAppear()
        }
        .onChange(of: appearance) { _, newAppearance in
            newAppearance.apply(to: NSApplication.shared)
        }
    }

    private var header: some View {
        HStack(spacing: 16) {
            Image(systemName: viewModel.connectionState == .connected ? "network.badge.shield.half.filled" : "shield.lefthalf.filled")
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: 60, height: 60)
                .background(AppTheme.magenta, in: RoundedRectangle(cornerRadius: 16))
            VStack(alignment: .leading, spacing: 5) {
                Text("VPN Helper").font(AppTheme.title)
                HStack(spacing: 6) {
                    Circle().fill(statusColor).frame(width: 7, height: 7)
                    Text(statusTitle).font(AppTheme.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if viewModel.isBusy { ProgressView().controlSize(.small) }
            appearanceMenu
        }
        .accessibilityElement(children: .contain)
    }

    private var appearanceMenu: some View {
        Menu {
            Picker("Appearance", selection: $appearance) {
                ForEach(AppAppearance.allCases) { option in
                    Label(option.title, systemImage: option.symbolName)
                        .tag(option)
                }
            }
            .pickerStyle(.inline)
        } label: {
            Image(systemName: appearance.symbolName)
                .font(.system(size: 15))
                .frame(width: 28, height: 28)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Appearance: \(appearance.title)")
        .accessibilityLabel("Appearance")
        .accessibilityValue(appearance.title)
    }

    private var credentials: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Your account").font(AppTheme.headline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Work email").font(AppTheme.callout).foregroundStyle(.secondary)
                HStack {
                    TextField("Username", text: $viewModel.emailPrefix)
                        .textContentType(.username)
                    Text(viewModel.emailDomain).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("VPN password").font(AppTheme.callout).foregroundStyle(.secondary)
                HStack {
                    Group {
                        if showVPNPassword {
                            TextField("Password", text: $viewModel.vpnPassword)
                        } else {
                            SecureField("Password", text: $viewModel.vpnPassword)
                        }
                    }
                    Button { showVPNPassword.toggle() } label: {
                        Image(systemName: showVPNPassword ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.plain)
                    .help(showVPNPassword ? "Hide password" : "Show password")
                    .accessibilityLabel(showVPNPassword ? "Hide password" : "Show password")
                }
            }
            Toggle("Save login in Keychain", isOn: Binding(
                get: { viewModel.rememberCredentials },
                set: { viewModel.setRememberCredentials($0) }
            ))
            Text("Your password stays in the macOS Keychain. A new OTP is required for each connection.")
                .font(AppTheme.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .textFieldStyle(.roundedBorder)
        .disabled(viewModel.isBusy || (viewModel.connectionState != .disconnected && viewModel.connectionState != .error))
    }

    private var connectionControls: some View {
        VStack(alignment: .leading, spacing: 12) {
            if viewModel.connectionState == .awaitingOTP {
                Text("Enter the code sent to your phone.").font(AppTheme.callout)
                OTPCodeField(code: $viewModel.otp, onSubmit: performPrimaryAction)
                    .disabled(viewModel.isBusy)
            }
            Button(action: performPrimaryAction) {
                Text(primaryTitle).frame(maxWidth: .infinity).padding(.vertical, 5)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.roundedRectangle(radius: 10))
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!primaryEnabled)
            if viewModel.connectionState == .awaitingOTP {
                Button("Cancel") { Task { await viewModel.disconnect() } }
                    .disabled(viewModel.isBusy)
            }
            if viewModel.connectionState == .disconnected {
                Text("Connect, enter your OTP, and you’re ready.")
                    .font(AppTheme.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var diagnostics: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button { showLogs.toggle() } label: {
                    Label("Connection log", systemImage: showLogs ? "chevron.down" : "chevron.right")
                }
                .buttonStyle(.plain)
                Spacer()
                Menu {
                    Button("Copy logs") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(formattedLogs, forType: .string)
                    }.disabled(viewModel.logs.isEmpty)
                    Button("Clear logs") { viewModel.logs.removeAll() }
                        .disabled(viewModel.logs.isEmpty)
                    Divider()
                    Button("Repair network") { Task { await viewModel.fixNetwork() } }
                        .disabled(!viewModel.canFixNetwork)
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Diagnostics")
            }
            .foregroundStyle(.secondary)
            if showLogs {
                ScrollView {
                    Text(formattedLogs.isEmpty ? "No connection activity yet." : formattedLogs)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
                .frame(height: 180)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    private var primaryTitle: String {
        if viewModel.connectionState == .awaitingOTP { return "Verify OTP" }
        if viewModel.canDisconnect { return viewModel.connectionState == .connected ? "Disconnect" : "Cancel connection" }
        if viewModel.isBusy { return "Connecting…" }
        return "Connect"
    }

    private var primaryEnabled: Bool {
        if viewModel.connectionState == .awaitingOTP { return viewModel.canSubmitOTP }
        return viewModel.canDisconnect || viewModel.canStartLogin
    }

    private func performPrimaryAction() {
        Task {
            if viewModel.connectionState == .awaitingOTP {
                await viewModel.submitOTP()
            } else if viewModel.canDisconnect {
                await viewModel.disconnect()
            } else if viewModel.canStartLogin {
                editLogin = false
                await viewModel.startLogin()
            }
        }
    }

    private var statusTitle: String {
        switch viewModel.connectionState {
        case .disconnected: "Ready to connect"
        case .authenticating: "Signing in…"
        case .awaitingOTP: "Waiting for your OTP"
        case .authenticated, .connecting: "Establishing secure connection…"
        case .connected: "Connected"
        case .disconnecting: "Disconnecting…"
        case .error: "Connection needs attention"
        }
    }

    private var statusColor: Color {
        switch viewModel.connectionState {
        case .connected: .green
        case .error: .orange
        case .disconnected: .secondary
        default: AppTheme.magenta
        }
    }

    private var formattedLogs: String {
        viewModel.logs.map {
            "[\($0.timestamp.formatted(date: .omitted, time: .standard))] \($0.message)"
        }.joined(separator: "\n")
    }
}

#Preview {
    ContentView(viewModel: VPNViewModel(service: MockVPNService()))
}
