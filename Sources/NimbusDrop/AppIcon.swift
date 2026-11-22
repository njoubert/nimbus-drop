// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import AppKit
import CoreGraphics
import Foundation

/// The app icon, drawn in code (no .icns checked in): a dark macOS squircle, a cloud (the
/// nimbus) and an arrow dropping out of it onto a line. The same glyph, in one colour, is the
/// menu bar item. `build.sh app` renders it to an .iconset → .icns; `build.sh icon` refreshes
/// docs/icon.png.
enum AppIcon {

    // Apple's macOS icon grid in a 1024-pt reference canvas: 824×824 body, radius 185.4.
    private static let ref: CGFloat = 1024
    private static let bodyInset: CGFloat = 100
    private static let bodyRadius: CGFloat = 185.4

    private static let green = rgb(0x3D, 0xE8, 0x9C)
    private static let blue = rgb(0x3A, 0xA8, 0xFF)

    /// The scale of the current render: shadow offsets and blurs are in *base* space (the
    /// CTM does not scale them), so every `setShadow` below multiplies by this.
    nonisolated(unsafe) private static var scale: CGFloat = 1

    /// The cloud in the 1024 canvas: three lobes on a flat base.
    static func cloudPath() -> CGPath {
        let p = CGMutablePath()
        p.addEllipse(in: CGRect(x: 262, y: 500, width: 220, height: 220))
        p.addEllipse(in: CGRect(x: 380, y: 540, width: 300, height: 300))
        p.addEllipse(in: CGRect(x: 580, y: 500, width: 190, height: 190))
        p.addRoundedRect(in: CGRect(x: 262, y: 500, width: 508, height: 150), cornerWidth: 75, cornerHeight: 75)
        return p
    }

    /// The arrow below the cloud and the line it lands on, as a path to stroke.
    static func arrowPath() -> CGPath {
        let p = CGMutablePath()
        p.move(to: CGPoint(x: 512, y: 432)); p.addLine(to: CGPoint(x: 512, y: 262))
        p.move(to: CGPoint(x: 432, y: 342)); p.addLine(to: CGPoint(x: 512, y: 262)); p.addLine(to: CGPoint(x: 592, y: 342))
        return p
    }

    static func landingPath() -> CGPath {
        let p = CGMutablePath()
        p.move(to: CGPoint(x: 372, y: 186)); p.addLine(to: CGPoint(x: 652, y: 186))
        return p
    }

    static func draw(in ctx: CGContext, size: CGFloat) {
        ctx.saveGState()
        scale = size / ref
        ctx.scaleBy(x: scale, y: scale)

        let body = CGRect(x: bodyInset, y: bodyInset, width: ref - 2 * bodyInset, height: ref - 2 * bodyInset)
        let shape = CGPath(roundedRect: body, cornerWidth: bodyRadius, cornerHeight: bodyRadius, transform: nil)

        // Shadow, as macOS icons carry their own; small enough to fade out inside the canvas.
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -12 * scale), blur: 28 * scale,
                      color: NSColor(calibratedWhite: 0, alpha: 0.45).cgColor)
        ctx.addPath(shape); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
        ctx.restoreGState()

        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()

        // Body: deep blue-graphite, lit from the top.
        fillLinear(ctx, from: CGPoint(x: 512, y: body.maxY), to: CGPoint(x: 512, y: body.minY),
                   stops: [(0, rgb(0x2A, 0x36, 0x4A)), (0.5, rgb(0x14, 0x1B, 0x27)), (1, rgb(0x08, 0x0B, 0x11))],
                   rect: body)
        drawGlow(ctx, center: CGPoint(x: 512, y: 300), radius: 430, color: rgb(0x2E, 0xE0, 0xC0), alpha: 0.20)

        // The cloud: near-white at the top to sky blue at the base, with a soft blue halo.
        let cloud = cloudPath()
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 40 * scale, color: blue.copy(alpha: 0.55))
        ctx.addPath(cloud); ctx.setFillColor(blue); ctx.fillPath()
        ctx.restoreGState()
        ctx.saveGState()
        ctx.addPath(cloud); ctx.clip()
        fillLinear(ctx, from: CGPoint(x: 0, y: 840), to: CGPoint(x: 0, y: 500),
                   stops: [(0, rgb(0xF4, 0xFA, 0xFF)), (1, rgb(0x8F, 0xCB, 0xFF))], rect: body)
        ctx.restoreGState()

        // The drop: a green arrow with a glow, and the line it lands on.
        for (path, color, width) in [(arrowPath(), green, CGFloat(62)), (landingPath(), blue, CGFloat(46))] {
            ctx.saveGState()
            ctx.setShadow(offset: .zero, blur: 34 * scale, color: color.copy(alpha: 0.6))
            ctx.addPath(path)
            ctx.setStrokeColor(color)
            ctx.setLineWidth(width); ctx.setLineCap(.round); ctx.setLineJoin(.round)
            ctx.strokePath()
            ctx.restoreGState()
        }

        // Top-edge highlight.
        ctx.addPath(shape)
        ctx.setStrokeColor(NSColor(calibratedWhite: 1, alpha: 0.14).cgColor)
        ctx.setLineWidth(3)
        ctx.strokePath()
        ctx.restoreGState()

        ctx.restoreGState()
    }

    /// The glyph alone as a template image for the menu bar: the cloud, the arrow, the line.
    /// `dimmed` (receiving is off) drops the arrow and the line and hollows the cloud.
    static func menuBarImage(dimmed: Bool) -> NSImage {
        let size = NSSize(width: 20, height: 18)
        let image = NSImage(size: size, flipped: false) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            // The glyph spans x 262…770, y 163…840 in the icon's canvas.
            let s = size.height / 700
            ctx.translateBy(x: (size.width - 508 * s) / 2 - 262 * s, y: -152 * s)
            ctx.scaleBy(x: s, y: s)
            ctx.setFillColor(NSColor.black.cgColor)
            ctx.setStrokeColor(NSColor.black.cgColor)
            ctx.setLineCap(.round); ctx.setLineJoin(.round)
            if dimmed {
                // The outline of the whole cloud, not of each lobe: the union first.
                ctx.addPath(cloudPath().normalized(using: .winding))
                ctx.setLineWidth(46)
                ctx.strokePath()
            } else {
                ctx.addPath(cloudPath()); ctx.fillPath()
                ctx.addPath(arrowPath()); ctx.setLineWidth(60); ctx.strokePath()
                ctx.addPath(landingPath()); ctx.setLineWidth(52); ctx.strokePath()
            }
            return true
        }
        image.isTemplate = true
        return image
    }

    // MARK: Helpers

    private static func rgb(_ r: Int, _ g: Int, _ b: Int) -> CGColor {
        CGColor(srgbRed: CGFloat(r) / 255, green: CGFloat(g) / 255, blue: CGFloat(b) / 255, alpha: 1)
    }

    private static func fillLinear(_ ctx: CGContext, from: CGPoint, to: CGPoint,
                                   stops: [(CGFloat, CGColor)], rect: CGRect) {
        guard let g = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB)!,
                                 colors: stops.map { $0.1 } as CFArray,
                                 locations: stops.map { $0.0 }) else { return }
        ctx.saveGState()
        ctx.clip(to: rect)
        ctx.drawLinearGradient(g, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        ctx.restoreGState()
    }

    private static func drawGlow(_ ctx: CGContext, center: CGPoint, radius: CGFloat, color: CGColor, alpha: CGFloat) {
        guard let g = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB)!,
                                 colors: [color.copy(alpha: alpha)!, color.copy(alpha: 0)!] as CFArray,
                                 locations: [0, 1]) else { return }
        ctx.drawRadialGradient(g, startCenter: center, startRadius: 0, endCenter: center, endRadius: radius, options: [])
    }

    // MARK: Rasterising

    static func cgImage(px: Int) -> CGImage? {
        guard let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        ctx.setAllowsAntialiasing(true)
        ctx.interpolationQuality = .high
        draw(in: ctx, size: CGFloat(px))
        return ctx.makeImage()
    }

    static func pngData(px: Int) -> Data? {
        guard let cg = cgImage(px: px) else { return nil }
        return NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])
    }

    /// Write an .iconset directory for `iconutil -c icns`.
    static func writeIconset(to dir: String) throws {
        let fm = FileManager.default
        try? fm.removeItem(atPath: dir)
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let variants: [(Int, Int)] = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2),
                                      (256, 1), (256, 2), (512, 1), (512, 2)]
        for (pt, scale) in variants {
            let name = scale == 1 ? "icon_\(pt)x\(pt).png" : "icon_\(pt)x\(pt)@2x.png"
            guard let data = pngData(px: pt * scale) else { continue }
            try data.write(to: URL(fileURLWithPath: dir).appendingPathComponent(name))
        }
    }
}
