import AppKit

let output = CommandLine.arguments[1]
for size in [16, 32, 64, 128, 256, 512, 1024] {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let scale = CGFloat(size) / 1024
    let transform = NSAffineTransform()
    transform.scale(by: scale)
    transform.concat()
    let tile = NSBezierPath(roundedRect: NSRect(x: 64, y: 64, width: 896, height: 896), xRadius: 200, yRadius: 200)
    NSColor(srgbRed: 226.0 / 255, green: 0, blue: 116.0 / 255, alpha: 1).setFill()
    tile.fill()
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: 512, y: 810))
    shield.curve(to: NSPoint(x: 745, y: 730), controlPoint1: NSPoint(x: 610, y: 760), controlPoint2: NSPoint(x: 690, y: 745))
    shield.line(to: NSPoint(x: 735, y: 495))
    shield.curve(to: NSPoint(x: 512, y: 230), controlPoint1: NSPoint(x: 730, y: 370), controlPoint2: NSPoint(x: 620, y: 285))
    shield.curve(to: NSPoint(x: 289, y: 495), controlPoint1: NSPoint(x: 404, y: 285), controlPoint2: NSPoint(x: 294, y: 370))
    shield.line(to: NSPoint(x: 279, y: 730))
    shield.curve(to: NSPoint(x: 512, y: 810), controlPoint1: NSPoint(x: 334, y: 745), controlPoint2: NSPoint(x: 414, y: 760))
    shield.close()
    NSColor.white.withAlphaComponent(0.97).setStroke()
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
    try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "\(output)/icon-\(size).png"))
}
