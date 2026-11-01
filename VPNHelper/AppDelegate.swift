import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Load from this bundle, rather than reusing a cached Dock icon from
        // another installed build with the same bundle identifier.
        guard let iconURL = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
              let icon = NSImage(contentsOf: iconURL) else {
            return
        }

        NSApplication.shared.applicationIconImage = icon
    }
}
