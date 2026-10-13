import Vapor
import Foundation

/// Names on public OpenPGP keys that mention an email address, from the
/// Ubuntu keyserver's machine-readable index (no key required).
///
/// Unlike keys.openpgp.org (`OpenPGPKeyPlugin`), this keyserver verifies
/// nothing: anyone can upload a key that names anyone's address. So a hit is
/// a lead, not a link. The name is kept at low confidence for identity
/// synthesis to weigh, and stays under the pivot threshold, so a planted key
/// can never steer the scan towards addresses an attacker chose.
///
/// API: GET https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&options=mr
struct PGPKeyserverPlugin: FootprintPlugin {
    let name = "PGPKeyserver"
    let description = "Names on public PGP keys that mention an email (unverified keyserver)"
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let email = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard email.range(of: #"^[^@\s"]+@[^@\s"]+\.[a-z]{2,}$"#, options: .regularExpression) != nil else { return [] }
        var components = URLComponents(string: "https://keyserver.ubuntu.com/pks/lookup")
        components?.queryItems = [URLQueryItem(name: "search", value: email), URLQueryItem(name: "op", value: "index"),
                                  URLQueryItem(name: "options", value: "mr")]
        guard let url = components?.url,
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/plain"], timeout: 15,
                bodyMode: .complete(maxBytes: 512 * 1_024), on: app
              ),
              // 404 is "no key mentions this address".
              response.status == 200,
              let text = String(bytes: response.data, encoding: .utf8) else { return [] }
        return Self.evaluate(email: email, index: text)
    }

    struct Key: Equatable {
        let fingerprint: String
        let created: String?
        var uids: [String] = []
    }

    /// Parses the machine-readable index (`pub:` lines, then their `uid:`
    /// lines, values percent-encoded).
    static func parse(_ index: String) -> [Key] {
        var keys: [Key] = []
        for line in index.split(whereSeparator: \.isNewline).prefix(5_000) {
            let fields = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            switch fields.first {
            case "pub" where fields.count > 4:
                let created = Double(fields[4]).flatMap { TimelineIntelligence.isoDay(unixTimestamp: $0) }
                keys.append(Key(fingerprint: fields[1].uppercased(), created: created))
            case "uid" where fields.count > 1 && !keys.isEmpty && keys[keys.count - 1].uids.count < 32:
                if let uid = fields[1].removingPercentEncoding?.trimmingCharacters(in: .whitespaces), !uid.isEmpty {
                    keys[keys.count - 1].uids.append(uid)
                }
            default:
                continue
            }
        }
        return keys
    }

    static func evaluate(email: String, index: String) -> [PluginResult] {
        parse(index).filter { key in key.uids.contains { $0.lowercased().contains("<\(email)>") || $0.lowercased() == email } }
            .prefix(3)
            .map { key in
                let names = key.uids.compactMap { uid -> String? in
                    guard let open = uid.firstIndex(of: "<") else { return uid.contains("@") ? nil : uid }
                    let name = uid[..<open].trimmingCharacters(in: .whitespaces)
                    return name.isEmpty ? nil : name
                }
                let shortID = String(key.fingerprint.suffix(16))
                var parts = ["A public PGP key (\(shortID)) names \(email); keyserver identities are not verified"]
                if let name = names.first { parts.append("Name on key: \(name)") }
                if let created = key.created { parts.append("Key created: \(created)") }
                // `account`, not `username`: a key ID is not a handle the person
                // uses, and must not be listed or pivoted on as one.
                var meta = ["platform": "pgp-key", "account": shortID.lowercased(), "email": email,
                            "matchKind": "inferred",
                            "matchReason": "a public key names this address, but anyone can upload such a key"]
                if let name = names.first { meta["name"] = name }
                return PluginResult(source: "PGP keyserver", type: "pgp_key_uid", confidenceScore: 0.5,
                                    rawData: parts.joined(separator: " | "), metadata: meta)
            }
    }
}
