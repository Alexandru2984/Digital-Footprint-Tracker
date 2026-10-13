import Vapor
import Foundation

/// Looks an email address up on keys.openpgp.org and reports the other
/// addresses on the same key (no key required).
///
/// That server publishes an identity only after its owner confirmed the
/// address by mail, so every address on a key it returns belongs to the same
/// person. That makes it one of the few keyless sources that ties one email to
/// another as a fact rather than a guess, and each linked address becomes a
/// pivot. It strips names, so what comes back is addresses and the key's age.
///
/// API: GET https://keys.openpgp.org/vks/v1/by-email/{email} → 200 armored key | 404
struct OpenPGPKeyPlugin: FootprintPlugin {
    let name = "OpenPGPKeys"
    let description = "Other verified emails on the same OpenPGP key (keys.openpgp.org)"
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let email = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard email.range(of: #"^[^@\s"/]+@[^@\s"/]+\.[a-z]{2,}$"#, options: .regularExpression) != nil,
              let encoded = email.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(.init(charactersIn: ".-_+"))),
              let url = URL(string: "https://keys.openpgp.org/vks/v1/by-email/\(encoded)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "application/pgp-keys"], timeout: 10,
                bodyMode: .complete(maxBytes: 512 * 1_024), on: app
              ),
              response.status == 200,
              let armored = String(bytes: response.data, encoding: .utf8),
              let key = OpenPGPKey.parse(armored: armored)
        else { return [] }
        return Self.results(email: email, key: key)
    }

    static func results(email: String, key: OpenPGPKey) -> [PluginResult] {
        // The lookup itself proves the key carries `email`; a key whose
        // identities do not include it is not the one asked about.
        let addresses = key.emails
        guard addresses.contains(email) else { return [] }
        let others = addresses.filter { $0 != email }
        let created = key.createdAt.flatMap { TimelineIntelligence.isoDay(unixTimestamp: $0.timeIntervalSince1970) }
        let keyAge = created.map { " (key created \($0))" } ?? ""

        guard !others.isEmpty else {
            var meta = ["platform": "openpgp", "email": email]
            if let created { meta["since"] = created }
            return [PluginResult(
                source: "OpenPGP", type: "identity_proof", confidenceScore: 0.9,
                rawData: "\(email) has a published OpenPGP key with a verified identity\(keyAge).",
                metadata: meta)]
        }
        return others.prefix(5).map { other in
            var meta = ["platform": "openpgp", "email": other, "linkedEmail": email, "matchKind": "verified",
                        "matchReason": "both addresses were confirmed by mail on the same OpenPGP key"]
            if let created { meta["since"] = created }
            return PluginResult(
                source: "OpenPGP", type: "identity_proof", confidenceScore: 1.0,
                rawData: "\(email) and \(other) are verified identities on the same OpenPGP key\(keyAge).",
                metadata: meta)
        }
    }
}

/// Just enough of RFC 4880 / 9580 to read a public key's user IDs and creation
/// time: armor, packet framing, the primary key's timestamp and User ID
/// packets. Everything else is skipped by length. Remote input, so every
/// length is bounds-checked and the packet count is capped.
struct OpenPGPKey: Equatable {
    let userIDs: [String]
    let createdAt: Date?

    /// Addresses in the user IDs (`Name <a@b>` or `<a@b>`), lowercased, in
    /// order, without duplicates.
    var emails: [String] {
        var seen: Set<String> = []
        return userIDs.compactMap { uid -> String? in
            let address: Substring
            if let open = uid.lastIndex(of: "<"), let close = uid.lastIndex(of: ">"), open < close {
                address = uid[uid.index(after: open)..<close]
            } else {
                address = Substring(uid)
            }
            let value = address.trimmingCharacters(in: .whitespaces).lowercased()
            guard value.contains("@"), !value.contains(" "), seen.insert(value).inserted else { return nil }
            return value
        }
    }

    static func parse(armored: String) -> Self? {
        guard let data = dearmor(armored) else { return nil }
        return parse(packets: data)
    }

    static func dearmor(_ text: String) -> Data? {
        let lines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let begin = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK") }),
              let end = lines.firstIndex(where: { $0.hasPrefix("-----END PGP PUBLIC KEY BLOCK") }),
              begin < end else { return nil }
        // Armor headers end at the first blank line; the CRC line starts "=".
        var body = Array(lines[(begin + 1)..<end])
        if let blank = body.firstIndex(of: "") { body = Array(body[(blank + 1)...]) }
        let base64 = body.filter { !$0.isEmpty && !$0.hasPrefix("=") }.joined()
        return Data(base64Encoded: base64)
    }

    static func parse(packets data: Data) -> Self? {
        let bytes = [UInt8](data)
        var index = 0
        var userIDs: [String] = []
        var createdAt: Date?
        var packets = 0
        while index < bytes.count, packets < 4_096 {
            packets += 1
            let header = bytes[index]
            guard header & 0x80 != 0 else { return nil }
            index += 1
            let tag: Int
            let length: Int
            if header & 0x40 != 0 {
                tag = Int(header & 0x3F)
                guard index < bytes.count else { return nil }
                let first = Int(bytes[index])
                if first < 192 {
                    length = first; index += 1
                } else if first < 224 {
                    guard index + 1 < bytes.count else { return nil }
                    length = ((first - 192) << 8) + Int(bytes[index + 1]) + 192; index += 2
                } else if first == 255 {
                    guard index + 4 < bytes.count else { return nil }
                    length = bytes[(index + 1)...(index + 4)].reduce(0) { $0 << 8 | Int($1) }; index += 5
                } else {
                    return nil   // partial lengths never frame key packets
                }
            } else {
                tag = Int((header >> 2) & 0x0F)
                switch header & 0x03 {
                case 0:
                    guard index < bytes.count else { return nil }
                    length = Int(bytes[index]); index += 1
                case 1:
                    guard index + 1 < bytes.count else { return nil }
                    length = Int(bytes[index]) << 8 | Int(bytes[index + 1]); index += 2
                case 2:
                    guard index + 3 < bytes.count else { return nil }
                    length = bytes[index...(index + 3)].reduce(0) { $0 << 8 | Int($1) }; index += 4
                default:
                    length = bytes.count - index
                }
            }
            guard length >= 0, index + length <= bytes.count else { return nil }
            let body = bytes[index..<(index + length)]
            switch tag {
            case 6 where createdAt == nil && body.count >= 5:
                // Primary key: version, then a four-byte creation time.
                let seconds = body.dropFirst().prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
                createdAt = Date(timeIntervalSince1970: TimeInterval(seconds))
            case 13 where userIDs.count < 64:
                if let uid = String(bytes: body, encoding: .utf8) { userIDs.append(uid) }
            default:
                break
            }
            index += length
        }
        guard !userIDs.isEmpty else { return nil }
        return Self(userIDs: userIDs, createdAt: createdAt)
    }
}
