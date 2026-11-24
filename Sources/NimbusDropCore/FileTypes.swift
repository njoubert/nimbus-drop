// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import UniformTypeIdentifiers
import NimbusBase
import NimbusCrypto
import NimbusNet
import NimbusSafeStorageCore
import NimbusSecurityCore
import NimbusDiscovery
import NimbusTransferCore

/// The kinds of file in a drop, so a sender can choose to send only some of them ("just the
/// JPEGs"). A kind is what macOS takes the extension to mean, so `.jpg` and `.jpeg` are one;
/// an extension macOS does not know is a kind of its own.
public struct FileKind: Identifiable, Equatable, Sendable {
    /// Stable for a kind: a type identifier ("public.jpeg"), "ext:xyz", "none" or "symlink".
    public var id: String
    /// "JPEG image", "XMP file", "Files with no extension".
    public var label: String
    /// The extensions seen for it in this drop, lower case, without the dot.
    public var extensions: [String]
    public var files: Int
    public var bytes: Int64

    public init(id: String, label: String, extensions: [String], files: Int, bytes: Int64) {
        self.id = id; self.label = label; self.extensions = extensions; self.files = files; self.bytes = bytes
    }
}

public enum FileKinds {
    /// The kind a path belongs to.
    public static func id(forPath path: String, isSymlink: Bool = false) -> String {
        if isSymlink { return "symlink" }
        let ext = (path as NSString).pathExtension.lowercased()
        if ext.isEmpty { return "none" }
        if let type = UTType(filenameExtension: ext), !type.identifier.hasPrefix("dyn.") { return type.identifier }
        return "ext:" + ext
    }

    private static func label(for id: String, extensions: [String]) -> String {
        switch id {
        case "none": return "Files with no extension"
        case "symlink": return "Symbolic links"
        default:
            if !id.hasPrefix("ext:"), let name = UTType(id)?.localizedDescription, !name.isEmpty {
                return name.prefix(1).uppercased() + name.dropFirst()
            }
            return (extensions.first ?? "").uppercased() + " file"
        }
    }

    /// Every kind in the drop, the one taking the most bytes first.
    public static func summarize(_ manifest: Manifest) -> [FileKind] {
        var found: [String: (extensions: Set<String>, files: Int, bytes: Int64)] = [:]
        for e in manifest.entries where e.kind != .directory {
            let id = id(forPath: e.path, isSymlink: e.kind == .symlink)
            let ext = (e.path as NSString).pathExtension.lowercased()
            var entry = found[id] ?? ([], 0, 0)
            if !ext.isEmpty, e.kind == .file { entry.extensions.insert(ext) }
            entry.files += 1
            entry.bytes += e.size
            found[id] = entry
        }
        return found.map { id, v in
            let exts = v.extensions.sorted()
            return FileKind(id: id, label: label(for: id, extensions: exts), extensions: exts, files: v.files, bytes: v.bytes)
        }
        .sorted { ($0.bytes, $0.files, $1.label) > ($1.bytes, $1.files, $0.label) }
    }
}

extension ScannedDrop {
    /// The same drop with only the files (and links) of the given kinds. Folders stay where
    /// something in them stays, so what arrives keeps its shape; folders the choice leaves empty
    /// are not sent.
    public func keeping(kinds: Set<String>) -> ScannedDrop {
        var needed = Set<String>()
        var keep = [Bool](repeating: false, count: manifest.entries.count)
        for (i, e) in manifest.entries.enumerated() where e.kind != .directory {
            guard kinds.contains(FileKinds.id(forPath: e.path, isSymlink: e.kind == .symlink)) else { continue }
            keep[i] = true
            var parent = (e.path as NSString).deletingLastPathComponent
            while !parent.isEmpty, needed.insert(parent).inserted { parent = (parent as NSString).deletingLastPathComponent }
        }
        for (i, e) in manifest.entries.enumerated() where e.kind == .directory { keep[i] = needed.contains(e.path) }
        var out = ScannedDrop(manifest: Manifest(chunkSize: manifest.chunkSize, entries: []), sources: [])
        for i in manifest.entries.indices where keep[i] {
            out.manifest.entries.append(manifest.entries[i])
            out.sources.append(sources[i])
        }
        return out
    }
}
