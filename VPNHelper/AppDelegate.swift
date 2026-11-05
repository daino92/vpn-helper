import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarController: VPNMenuBarController?

    func register(window: NSWindow, model: VPNViewModel) {
        guard menuBarController == nil else { return }
        menuBarController = VPNMenuBarController(model: model, window: window)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        menuBarController?.showWindow()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

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
