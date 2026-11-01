import AppKit

/// sudo launches a separate, unprivileged process to collect the Mac password.
/// The password goes directly to sudo through stdout and is never persisted.
@MainActor
enum NativeAdminPrompt {
    static func askpassScript(executablePath: String) -> String {
        let quotedPath = "'" + executablePath.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return "#!/bin/sh\nexec \(quotedPath) --sudo-askpass\n"
    }

    static func run() -> Never {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let appearance = AppAppearance(rawValue: UserDefaults.standard.string(forKey: "appearance") ?? "system") ?? .system
        appearance.apply(to: application)

        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.icon = NSImage(named: NSImage.applicationIconName)
        alert.messageText = "VPN Helper needs administrator access"
        alert.informativeText = "Enter the login password for your Mac to allow VPN Helper to configure the VPN connection or repair network settings. This is not your VPN password."
        alert.addButton(withTitle: "Allow")
        alert.addButton(withTitle: "Cancel")
        alert.buttons[1].keyEquivalent = "\u{1b}"

        let passwordField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        passwordField.placeholderString = "Mac login password"
        passwordField.setAccessibilityLabel("Mac login password")
        alert.accessoryView = passwordField
        alert.window.initialFirstResponder = passwordField
        application.activate(ignoringOtherApps: true)

        guard alert.runModal() == .alertFirstButtonReturn else {
            exit(EXIT_FAILURE)
        }

        let password = passwordField.stringValue
        passwordField.stringValue = ""
        guard !password.isEmpty, let data = (password + "\n").data(using: .utf8) else {
            exit(EXIT_FAILURE)
        }

        do {
            try FileHandle.standardOutput.write(contentsOf: data)
            exit(EXIT_SUCCESS)
        } catch {
            exit(EXIT_FAILURE)
        }
    }
}
