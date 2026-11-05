import AppKit
import Combine
import SwiftUI

/// Uses the same model as the window; hiding the window does not stop the VPN.
@MainActor
final class VPNMenuBarController: NSObject, NSMenuDelegate {
    private let model: VPNViewModel
    private weak var window: NSWindow?
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var subscription: AnyCancellable?

    init(model: VPNViewModel, window: NSWindow) {
        self.model = model
        self.window = window
        super.init()
        subscription = model.$connectionState.removeDuplicates().sink { [weak self] state in
            self?.update(state)
            if state == .connected {
                self?.window?.orderOut(nil)
            }
        }
    }

    private func update(_ state: VPNConnectionState) {
        let title: String
        let color: NSColor
        switch state {
        case .connected:
            title = "Connected"
            color = .systemGreen
        case .disconnected:
            title = "Disconnected"
            color = .systemGray
        case .error:
            title = "Connection needs attention"
            color = .systemOrange
        default:
            title = "Connection in progress"
            color = .systemOrange
        }
        item.button?.image = statusImage(color: color)
        item.button?.toolTip = "VPN Helper — \(title)"
        item.button?.setAccessibilityLabel("VPN Helper, \(title)")

        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.delegate = self
        let status = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())
        menu.addItem(action("Open VPN Helper", selector: #selector(showWindow)))
        let disconnect = action("Disconnect", selector: #selector(disconnectVPN))
        disconnect.isEnabled = model.canDisconnect
        menu.addItem(disconnect)
        item.menu = menu
    }

    func menuWillOpen(_ menu: NSMenu) {
        menu.items.first { $0.action == #selector(disconnectVPN) }?.isEnabled = model.canDisconnect
    }

    private func action(_ title: String, selector: Selector) -> NSMenuItem {
        let entry = NSMenuItem(title: title, action: selector, keyEquivalent: "")
        entry.target = self
        return entry
    }

    @objc func showWindow() {
        window?.deminiaturize(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    @objc private func disconnectVPN() {
        guard model.canDisconnect else { return }
        Task { await model.disconnect() }
    }

    private func statusImage(color: NSColor) -> NSImage {
        let image = NSImage(size: NSSize(width: 27, height: 22), flipped: false) { _ in
            NSGraphicsContext.saveGraphicsState()
            let transform = NSAffineTransform()
            transform.translateX(by: -5, yBy: -4)
            transform.scale(by: 0.029)
            transform.concat()
            let shield = NSBezierPath()
            shield.move(to: NSPoint(x: 512, y: 810))
            shield.curve(to: NSPoint(x: 745, y: 730), controlPoint1: NSPoint(x: 610, y: 760), controlPoint2: NSPoint(x: 690, y: 745))
            shield.line(to: NSPoint(x: 735, y: 495))
            shield.curve(to: NSPoint(x: 512, y: 230), controlPoint1: NSPoint(x: 730, y: 370), controlPoint2: NSPoint(x: 620, y: 285))
            shield.curve(to: NSPoint(x: 289, y: 495), controlPoint1: NSPoint(x: 404, y: 285), controlPoint2: NSPoint(x: 294, y: 370))
            shield.line(to: NSPoint(x: 279, y: 730))
            shield.curve(to: NSPoint(x: 512, y: 810), controlPoint1: NSPoint(x: 334, y: 745), controlPoint2: NSPoint(x: 414, y: 760))
            shield.close()
            NSColor(srgbRed: 226.0 / 255, green: 0, blue: 116.0 / 255, alpha: 1).setStroke()
            shield.lineWidth = 42
            shield.lineJoinStyle = .round
            shield.stroke()
            // Two interlocking links represent the VPN tunnel inside the shield.
            let linksTransform = NSAffineTransform()
            linksTransform.translateX(by: 512, yBy: 520)
            linksTransform.rotate(byDegrees: 40)
            linksTransform.concat()
            let upperLink = NSBezierPath(roundedRect: NSRect(x: -145, y: -56, width: 195, height: 112), xRadius: 56, yRadius: 56)
            let lowerLink = NSBezierPath(roundedRect: NSRect(x: -50, y: -56, width: 195, height: 112), xRadius: 56, yRadius: 56)
            upperLink.lineWidth = 30
            lowerLink.lineWidth = 30
            upperLink.stroke()
            lowerLink.stroke()
            NSGraphicsContext.restoreGraphicsState()
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: 20, y: 2, width: 6, height: 6)).fill()
            return true
        }
        // Preserve the colored connection badge in the menu bar.
        image.isTemplate = false
        return image
    }
}

/// Captures only this scene's window, never an administrator password panel.
struct VPNWindowRegistration: NSViewRepresentable {
    let register: (NSWindow) -> Void

    func makeNSView(context: Context) -> WindowView {
        let view = WindowView()
        view.register = register
        return view
    }

    func updateNSView(_ nsView: WindowView, context: Context) {}

    final class WindowView: NSView {
        var register: ((NSWindow) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { register?(window) }
        }
    }
}
