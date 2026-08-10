import Foundation
import Crypto

/// RFC 6238 time-based one-time passwords (TOTP) — the algorithm every
/// authenticator app (Aegis, Google Authenticator, 1Password, …) speaks.
///
/// Pure Swift on top of swift-crypto's HMAC; no third-party dependency. Uses
/// HMAC-SHA1 with a 30-second step and 6 digits, which is what authenticator
/// apps default to when they scan an `otpauth://` URI that omits those params.
///
/// The shared secret is 20 random bytes, exchanged with the app as base32. It is
/// stored encrypted at rest (see `TokenEncryption`); this type only deals with
/// the raw secret in memory.
enum TOTP {
    static let digits = 6
    static let period = 30

    /// Generate a fresh 160-bit secret, returned base32-encoded (no padding),
    /// which is the form authenticator apps expect.
    static func generateSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 20)
        for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
        return base32Encode(bytes)
    }

    /// The `otpauth://totp/...` provisioning URI the client renders as a QR code.
    static func provisioningURI(secret: String, account: String, issuer: String) -> String {
        let label = "\(issuer):\(account)".addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? account
        let iss = issuer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? issuer
        return "otpauth://totp/\(label)?secret=\(secret)&issuer=\(iss)&algorithm=SHA1&digits=\(digits)&period=\(period)"
    }

    /// Verify `code` against `secret` at `date`, tolerating ±`window` steps of
    /// clock drift (default ±1 → accepts the previous, current, and next code).
    /// Constant-time digit comparison.
    static func verify(code: String, secret: String, at date: Date = Date(), window: Int = 1) -> Bool {
        matchedStep(code: code, secret: secret, at: date, window: window) != nil
    }

    /// Like `verify`, but returns the matched time-step counter so the caller can
    /// enforce single-use (reject a code at or below the last accepted step —
    /// RFC 6238 §5.2 replay protection). Constant-time digit comparison.
    static func matchedStep(code: String, secret: String, at date: Date = Date(), window: Int = 1) -> Int? {
        let cleaned = code.filter { $0.isNumber }
        guard cleaned.count == digits, let key = base32Decode(secret) else { return nil }
        let counter = Int(date.timeIntervalSince1970) / period
        for offset in -window...window {
            let step = counter + offset
            let candidate = generate(key: key, counter: UInt64(bitPattern: Int64(step)))
            if constantTimeEqual(candidate, cleaned) { return step }
        }
        return nil
    }

    /// The current code (used only in tests / debugging).
    static func current(secret: String, at date: Date = Date()) -> String? {
        guard let key = base32Decode(secret) else { return nil }
        return generate(key: key, counter: UInt64(Int(date.timeIntervalSince1970) / period))
    }

    // MARK: - Core

    private static func generate(key: [UInt8], counter: UInt64) -> String {
        var c = counter.bigEndian
        let msg = withUnsafeBytes(of: &c) { Array($0) }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: SymmetricKey(data: key))
        let hash = Array(mac)
        let offset = Int(hash[hash.count - 1] & 0x0f)
        let binary = (UInt32(hash[offset] & 0x7f) << 24)
            | (UInt32(hash[offset + 1]) << 16)
            | (UInt32(hash[offset + 2]) << 8)
            | UInt32(hash[offset + 3])
        let otp = binary % UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)u", otp)
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    // MARK: - Base32 (RFC 4648, no padding)

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static func base32Encode(_ data: [UInt8]) -> String {
        var out = ""
        var buffer = 0, bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 0x1f])
            }
        }
        if bits > 0 { out.append(alphabet[(buffer << (5 - bits)) & 0x1f]) }
        return out
    }

    static func base32Decode(_ string: String) -> [UInt8]? {
        var lookup = [Character: Int]()
        for (i, c) in alphabet.enumerated() { lookup[c] = i }
        var out = [UInt8](), buffer = 0, bits = 0
        for ch in string.uppercased() where ch != "=" && !ch.isWhitespace {
            guard let val = lookup[ch] else { return nil }
            buffer = (buffer << 5) | val
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> bits) & 0xff))
            }
        }
        return out
    }
}

/// One-time recovery codes: a printable fallback for when the authenticator is
/// lost. Stored only as SHA-256 hashes; the plaintext is shown to the user once.
enum RecoveryCodes {
    /// Generate `count` human-friendly codes (e.g. `a1b2-c3d4-e5f6`).
    static func generate(count: Int = 10) -> [String] {
        let chars = Array("abcdefghjkmnpqrstuvwxyz23456789") // no ambiguous 0/o/1/l/i
        func group() -> String { String((0..<4).map { _ in chars.randomElement()! }) }
        return (0..<count).map { _ in "\(group())-\(group())-\(group())" }
    }

    static func hash(_ code: String) -> String {
        let normalized = code.lowercased().filter { $0.isLetter || $0.isNumber }
        let digest = SHA256.hash(data: Data(normalized.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
