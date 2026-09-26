import AppKit
let args = CommandLine.arguments
guard args.count == 3, let source = NSImage(contentsOfFile: args[1]) else {
    fatalError("Usage: render-macos-icon.swift SOURCE.png OUTPUT.png")
}
let canvas = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 1024, pixelsHigh: 1024,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: canvas)
NSGraphicsContext.current!.imageInterpolation = .high
let bounds = NSRect(x: 64, y: 64, width: 896, height: 896)
let shape = NSBezierPath(roundedRect: bounds, xRadius: 196, yRadius: 196)
NSGraphicsContext.saveGraphicsState()
shape.addClip()
NSColor.black.setFill()
shape.fill()
let inset = source.size.width * 0.04
let crop = NSRect(x: inset, y: inset, width: source.size.width - inset * 2,
                  height: source.size.height - inset * 2)
source.draw(in: bounds, from: crop, operation: .sourceOver, fraction: 1)
NSGraphicsContext.restoreGraphicsState()
NSColor.white.withAlphaComponent(0.85).setStroke()
let border = NSBezierPath(roundedRect: bounds.insetBy(dx: 4, dy: 4), xRadius: 192, yRadius: 192)
border.lineWidth = 8
border.stroke()
NSGraphicsContext.restoreGraphicsState()
try canvas.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
