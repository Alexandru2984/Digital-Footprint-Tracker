import Vapor
import Foundation

/// Finds the Keybase users who hold a signed proof for an account or domain:
/// the reverse of `KeybasePlugin`, which reads the proofs of a known Keybase
/// user (no key required).
///
/// For a username it asks who proved `github:<name>` and `twitter:<name>`;
/// for a domain, who proved control of it (DNS or a file on the site). Keybase
/// answers with candidate users and sometimes more than one, so a user is only
/// reported if it holds a *live* proof for exactly that service and handle.
///
/// What a hit means: the Keybase account and the proven account belong to the
/// same person, as a cryptographic fact. Whether the proven account is the
/// target's is a separate question, answered by how the scan reached it.
///
/// API: GET https://keybase.io/_/api/1.0/user/lookup.json?{service}={handle}
struct KeybaseProofPlugin: FootprintPlugin {
    let name = "KeybaseProofs"
    let description = "Keybase users with a signed proof for this GitHub/Twitter name or domain"
    let accepts: Set<TargetShape> = [.username, .domain]
    let cacheTTL: TimeInterval = 86_400

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let isDomain = TargetShape.shapes(of: value).contains(.domain)
        let queries: [(param: String, services: Set<String>)] = isDomain
            ? [("domain", ["dns", "generic_web_site"])]
            : [("github", ["github"]), ("twitter", ["twitter"])]
        guard value.range(of: #"^[a-z0-9][a-z0-9._-]{0,252}$"#, options: .regularExpression) != nil else { return [] }

        var results: [PluginResult] = []
        for query in queries {
            var components = URLComponents(string: "https://keybase.io/_/api/1.0/user/lookup.json")
            components?.queryItems = [URLQueryItem(name: query.param, value: value),
                                      URLQueryItem(name: "fields", value: "basics,proofs_summary")]
            guard let url = components?.url,
                  let response = await PluginHTTP.request(
                    url, headers: ["Accept": "application/json"], timeout: 10,
                    bodyMode: .complete(maxBytes: 1_024 * 1_024), on: app
                  ),
                  response.status == 200 else { continue }
            // One result per Keybase user: proving both github:x and twitter:x
            // is one person found twice, not two findings.
            for result in Self.evaluate(body: response.data, handle: value, services: query.services, isDomain: isDomain)
            where !results.contains(where: { $0.metadata?["username"] == result.metadata?["username"] }) {
                results.append(result)
            }
        }
        return results
    }

    /// One result per Keybase user holding a live proof for `handle` on one
    /// of `services`; every other proof of that user is listed as `linked`.
    static func evaluate(body: Data, handle: String, services: Set<String>, isDomain: Bool) -> [PluginResult] {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let them = json["them"] as? [Any] else { return [] }
        return them.compactMap { $0 as? [String: Any] }.prefix(5).compactMap { user -> PluginResult? in
            guard let username = ((user["basics"] as? [String: Any])?["username"] as? String)?.lowercased(),
                  let all = (user["proofs_summary"] as? [String: Any])?["all"] as? [[String: Any]] else { return nil }
            let proofs = KeybasePlugin.liveProofs(all)
            guard let match = proofs.first(where: { services.contains($0.type) && $0.handle.lowercased() == handle })
            else { return nil }

            let others = proofs.filter { !($0.type == match.type && $0.handle.lowercased() == handle) }
            let profileURL = "https://keybase.io/\(username)"
            var parts = ["Keybase user \(username) holds a signed proof for \(match.type) \(handle): \(profileURL)"]
            if !others.isEmpty {
                parts.append("Also proven: " + others.prefix(8).map { "\($0.type) \($0.handle)" }.joined(separator: ", "))
            }
            var meta = ["platform": "keybase", "username": username, "profileURL": profileURL,
                        // The proven account and this one are one person.
                        "linked": IdentityLinks.linked(proofs.map { ($0.type, $0.handle) }) ?? "",
                        "linkKind": "verified", "linkReason": "Keybase holds a signed proof for this account"]
            if isDomain {
                // The domain itself is what was proven: its owner holds this account.
                meta["matchKind"] = "verified"
                meta["matchReason"] = "proved control of this domain on Keybase"
            } else {
                meta["matchReason"] = "holds a Keybase proof for the \(match.type) account \(handle); "
                    + "that account is the target's only if something else ties it to them"
            }
            return PluginResult(source: "Keybase", type: "identity_proof", confidenceScore: 0.95,
                                rawData: parts.joined(separator: " | "), metadata: meta)
        }
    }
}
