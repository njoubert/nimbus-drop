// Copyright (C) 2026 Niels Joubert
// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Darwin
import Foundation
import IOKit
import NimbusBase
import NimbusCrypto
import NimbusNet

/// The trust file on disk, sealed so that it opens only on the Mac that made it.
///
/// Two files in one folder. `device`: a P-256 key held by this Mac's Secure Enclave (in the
/// opaque form only that chip can use), a P-256 public key `w` made once, and this Mac's
/// hardware id. It is written once and never again: it survives the identity key being replaced.
/// `trust`: everything `Trust` keeps, sealed with AES-256-GCM under a key derived from the
/// agreement between the enclave's key and `w`.
///
/// A copy of both files on other hardware cannot be opened (checked 2026-11-22: the enclave
/// there loads the key and then cannot use it), so a backup, Migration Assistant or a stolen
/// disk image does not carry the identity. Software running as the same user on this Mac can ask
/// the enclave the same question this does; that was never claimed otherwise.
///
/// Not the Keychain: the keychain that can keep an item on one device needs an entitlement
/// backed by a provisioning profile, which a command-line binary cannot have, and the login
/// keychain both travels with a migration and refuses to work over ssh (both checked the same day).
public final class EnclaveStorage: TrustStorage, @unchecked Sendable {
    private struct Device: Codable {
        var enclave: Data?
        var w: Data
        var hardware: String
        /// Only on a Mac with no Secure Enclave (a virtual machine): the wrapping key itself.
        /// The file is then protected by its permissions alone, and says so in the log.
        var plain: Data?
    }

    private let folder: URL
    private var key: SymmetricKey?
    private let lock = NSLock()

    public init(folder: URL) { self.folder = folder }

    /// `~/Library/Application Support/<bundle id>` for the app; a folder of its own for each
    /// command-line `--name`.
    public static func standard(bundleID: String, name: String? = nil) -> EnclaveStorage {
        var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent(bundleID, isDirectory: true)
        if let name { dir.appendPathComponent("cli-" + name, isDirectory: true) }
        return EnclaveStorage(folder: dir)
    }

    private var deviceURL: URL { folder.appendingPathComponent("device") }
    private var trustURL: URL { folder.appendingPathComponent("trust") }

    static var hardwareID: String {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(entry) }
        return (IORegistryEntryCreateCFProperty(entry, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String) ?? "unknown"
    }

    private static let associated = Data("nimbus-drop trust v1".utf8) + Data([1])

    /// The wrapping key, from the device file; made on a first run.
    private func wrappingKey(create: Bool) throws -> SymmetricKey? {
        if let key { return key }
        let fm = FileManager.default
        var device: Device
        if let data = try? Data(contentsOf: deviceURL) {
            guard let d = try? JSONDecoder().decode(Device.self, from: data) else { throw TrustFault.damaged }
            device = d
            // Made on another Mac: nothing here can be opened, and nothing is wrong with this Mac.
            guard device.hardware == EnclaveStorage.hardwareID else { throw TrustFault.foreign }
        } else {
            guard create else { return nil }
            try fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let w = P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation
            if SecureEnclave.isAvailable {
                let enclave: SecureEnclave.P256.KeyAgreement.PrivateKey
                do { enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey() } catch { throw TrustFault.unavailable("\(error.localizedDescription)") }
                device = Device(enclave: enclave.dataRepresentation, w: w, hardware: EnclaveStorage.hardwareID)
            } else {
                DropLog.write("identity: this Mac has no Secure Enclave; the identity is protected by file permissions only", .warn)
                device = Device(enclave: nil, w: w, hardware: EnclaveStorage.hardwareID, plain: Crypto.random(32))
            }
            try write(try JSONEncoder().encode(device), to: deviceURL)
        }
        let derived: SymmetricKey
        if let blob = device.enclave {
            do {
                let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
                let shared = try enclave.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(rawRepresentation: device.w))
                derived = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("nimbus-drop trust v1".utf8), outputByteCount: 32)
            } catch { throw TrustFault.unavailable("\(error.localizedDescription)") }
        } else if let plain = device.plain {
            derived = SymmetricKey(data: plain)
        } else {
            throw TrustFault.damaged
        }
        key = derived
        return derived
    }

    public func load() throws -> Data? {
        try lock.withLock {
            let fm = FileManager.default
            let haveDevice = fm.fileExists(atPath: deviceURL.path), haveTrust = fm.fileExists(atPath: trustURL.path)
            if !haveDevice, !haveTrust { return nil }
            // A trust file without the key that opens it cannot be told from damage.
            guard haveDevice else { throw TrustFault.damaged }
            guard let key = try wrappingKey(create: false) else { return nil }
            guard haveTrust else { return nil }
            guard let sealed = try? Data(contentsOf: trustURL), let box = try? AES.GCM.SealedBox(combined: sealed),
                  let plain = try? AES.GCM.open(box, using: key, authenticating: EnclaveStorage.associated) else { throw TrustFault.damaged }
            return plain
        }
    }

    /// One atomic replacement: the whole new file written beside the old one, forced to the
    /// disk, renamed over it, and the folder forced too. A random nonce for every write.
    public func save(_ data: Data) throws {
        try lock.withLock {
            guard let key = try wrappingKey(create: true) else { throw TrustFault.damaged }
            let lockFD = open(folder.appendingPathComponent("lock").path, O_CREAT | O_RDWR, 0o600)
            defer { if lockFD >= 0 { flock(lockFD, LOCK_UN); close(lockFD) } }
            if lockFD >= 0 { flock(lockFD, LOCK_EX) }
            guard let sealed = try AES.GCM.seal(data, using: key, authenticating: EnclaveStorage.associated).combined else { throw TrustFault.damaged }
            try write(sealed, to: trustURL)
        }
    }

    private func write(_ data: Data, to url: URL) throws {
        let temp = url.appendingPathExtension("new-\(getpid())")
        let fd = open(temp.path, O_CREAT | O_WRONLY | O_TRUNC, 0o600)
        guard fd >= 0 else { throw errnoError("Cannot write \(temp.path)") }
        let ok = data.withUnsafeBytes { raw -> Bool in
            var done = 0
            while done < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + done, raw.count - done)
                if n > 0 { done += n } else if errno != EINTR { return false }
            }
            return fsync(fd) == 0
        }
        close(fd)
        guard ok, rename(temp.path, url.path) == 0 else {
            unlink(temp.path)
            throw errnoError("Cannot write \(url.path)")
        }
        let dir = open(folder.path, O_RDONLY)
        if dir >= 0 { fsync(dir); close(dir) }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var u = url
        try? u.setResourceValues(values)
    }

    /// Moves both files out of the way, untouched.
    public func setAside(_ label: String) {
        lock.withLock {
            key = nil
            let stamp = Int(Date().timeIntervalSince1970)
            for url in [deviceURL, trustURL] where FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.moveItem(at: url, to: url.appendingPathExtension("\(label)-\(stamp)"))
            }
        }
    }
}
