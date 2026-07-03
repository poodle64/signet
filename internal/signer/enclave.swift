// se_swift.swift: CryptoKit Secure Enclave shim for signet, exposed to Go (cgo)
// as plain C functions via @_cdecl.
//
// Why CryptoKit and not the Security-framework C API: a Secure Enclave private
// key is non-exportable, so the only ways to keep one are (a) persist a key
// REFERENCE in the data-protection keychain, which is gated by the
// com.apple.application-identifier entitlement (a registered App ID, hence
// Apple-team code-signing) and fails on an unsigned binary with -34018
// errSecMissingEntitlement; or (b) take the Enclave's OPAQUE, hardware-wrapped
// key blob (dataRepresentation) and store it yourself. CryptoKit exposes (b);
// the C API does not. The blob never leaves this Enclave's reach (it is useless
// on any other machine), so storing it in a plain file needs NO entitlement and
// NO code signature. This mirrors how age-plugin-se reaches the Enclave unsigned.
//
// Each function writes its outputs into caller-provided buffers and returns 0 on
// success or a negative code on failure, with a human-readable message in errBuf.
//
// Return-code convention (shared across all three functions):
//   -1  precondition failed (SE unavailable, empty blob)
//   -2  caller buffer too small
//   -4  CryptoKit operation failed (thrown error)
// signet_se_create_key also uses -3 when the public key buffer is too small
// (the blob write succeeded but the pub-key write failed).

import Foundation
import CryptoKit
import Security

private struct SEError: Error { let msg: String }

// setError copies a NUL-terminated message into the caller's error buffer.
private func setError(_ buf: UnsafeMutablePointer<CChar>?, _ cap: Int32, _ msg: String) {
    guard let buf = buf, cap > 0 else { return }
    let bytes = Array(msg.utf8.prefix(Int(cap) - 1))
    bytes.withUnsafeBytes { raw in
        if let base = raw.baseAddress, !bytes.isEmpty {
            memcpy(buf, base, bytes.count)
        }
    }
    buf[bytes.count] = 0
}

// copyOut writes data into a caller buffer, always reporting the true length in
// outLen. Returns false (without copying) if the buffer is too small.
private func copyOut(_ data: Data,
                     _ out: UnsafeMutablePointer<UInt8>?,
                     _ cap: Int32,
                     _ outLen: UnsafeMutablePointer<Int32>?) -> Bool {
    outLen?.pointee = Int32(data.count)
    guard let out = out, Int(cap) >= data.count else { return false }
    if !data.isEmpty {
        data.copyBytes(to: out, count: data.count)
    }
    return true
}

// makeAccess builds the SecAccessControl for a new key. privateKeyUsage is always
// set; user presence (Touch ID / passcode) is added on request. Accessibility is
// AfterFirstUnlockThisDeviceOnly: signet is a background machine-identity signer,
// so an unattended consumer (e.g. an MCP server) must be able to attest while the
// screen is locked, provided the Mac has been unlocked at least once since boot.
// WhenUnlocked would refuse to sign on a locked screen (errSecInteractionNotAllowed
// -25308), breaking exactly that use case. The key never leaves the Enclave and is
// device-bound; per-signature human approval is the orthogonal opt-in via
// userPresence (which does require a present, unlocked user at signing time).
private func makeAccess(userPresence: Bool) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if userPresence {
        flags.insert(.userPresence)
    }
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        flags,
        &err
    ) else {
        let m = err.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
            ?? "SecAccessControlCreateWithFlags failed"
        throw SEError(msg: m)
    }
    return access
}

// signet_se_available reports whether this Mac has a usable Secure Enclave.
@_cdecl("signet_se_available")
public func signet_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

// signet_se_create_key creates a fresh Secure Enclave P-256 signing key and
// returns its opaque wrapped blob (to be stored by the caller) and the public
// key as a 65-byte X9.63 uncompressed point (0x04 || X || Y).
@_cdecl("signet_se_create_key")
public func signet_se_create_key(
    _ userPresence: Int32,
    _ blobOut: UnsafeMutablePointer<UInt8>?, _ blobCap: Int32, _ blobLen: UnsafeMutablePointer<Int32>?,
    _ pubOut: UnsafeMutablePointer<UInt8>?, _ pubCap: Int32, _ pubLen: UnsafeMutablePointer<Int32>?,
    _ errBuf: UnsafeMutablePointer<CChar>?, _ errCap: Int32
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        setError(errBuf, errCap, "Secure Enclave is not available on this Mac")
        return -1
    }
    do {
        let access = try makeAccess(userPresence: userPresence != 0)
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        guard copyOut(key.dataRepresentation, blobOut, blobCap, blobLen) else {
            setError(errBuf, errCap, "key blob buffer too small")
            return -2
        }
        guard copyOut(key.publicKey.x963Representation, pubOut, pubCap, pubLen) else {
            setError(errBuf, errCap, "public key buffer too small")
            return -3
        }
        return 0
    } catch {
        let msg = (error as? SEError)?.msg ?? "create Secure Enclave key: \(error)"
        setError(errBuf, errCap, msg)
        return -4
    }
}

// signet_se_public_key reconstructs a key from its stored blob and returns the
// public key as a 65-byte X9.63 uncompressed point.
@_cdecl("signet_se_public_key")
public func signet_se_public_key(
    _ blobIn: UnsafePointer<UInt8>?, _ blobInLen: Int32,
    _ pubOut: UnsafeMutablePointer<UInt8>?, _ pubCap: Int32, _ pubLen: UnsafeMutablePointer<Int32>?,
    _ errBuf: UnsafeMutablePointer<CChar>?, _ errCap: Int32
) -> Int32 {
    guard let blobIn = blobIn, blobInLen > 0 else {
        setError(errBuf, errCap, "empty key blob")
        return -1
    }
    do {
        let blob = Data(bytes: blobIn, count: Int(blobInLen))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        guard copyOut(key.publicKey.x963Representation, pubOut, pubCap, pubLen) else {
            setError(errBuf, errCap, "public key buffer too small")
            return -2
        }
        return 0
    } catch {
        setError(errBuf, errCap, "load Secure Enclave key: \(error)")
        return -4
    }
}

// signet_se_sign reconstructs a key from its blob, signs the message (ECDSA over
// the SHA-256 digest, computed internally by CryptoKit), and returns the 64-byte
// IEEE P1363 r || s signature.
@_cdecl("signet_se_sign")
public func signet_se_sign(
    _ blobIn: UnsafePointer<UInt8>?, _ blobInLen: Int32,
    _ msgIn: UnsafePointer<UInt8>?, _ msgInLen: Int32,
    _ sigOut: UnsafeMutablePointer<UInt8>?, _ sigCap: Int32, _ sigLen: UnsafeMutablePointer<Int32>?,
    _ errBuf: UnsafeMutablePointer<CChar>?, _ errCap: Int32
) -> Int32 {
    guard let blobIn = blobIn, blobInLen > 0 else {
        setError(errBuf, errCap, "empty key blob")
        return -1
    }
    do {
        let blob = Data(bytes: blobIn, count: Int(blobInLen))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let msg = (msgIn != nil && msgInLen > 0) ? Data(bytes: msgIn!, count: Int(msgInLen)) : Data()
        let signature = try key.signature(for: msg)
        guard copyOut(signature.rawRepresentation, sigOut, sigCap, sigLen) else {
            setError(errBuf, errCap, "signature buffer too small")
            return -2
        }
        return 0
    } catch {
        setError(errBuf, errCap, "Secure Enclave sign: \(error)")
        return -4
    }
}
