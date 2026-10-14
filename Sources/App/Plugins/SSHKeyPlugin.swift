import Vapor
import Foundation
import Crypto

/// Compares the public SSH keys a username publishes on GitHub, GitLab and
/// Codeberg (no key required). Each serves an account's keys as plain text at
/// `https://{host}/{username}.keys`.
///
/// A key on two accounts ties them: the people who hold that private key
/// signed in to both. It is not a proof, since a public key is public and a
/// stranger could add someone else's to their own account, so the link is
/// `observed`, not `verified`. It is still far stronger than the shared name
/// that found the accounts in the first place.
struct SSHKeyPlugin: FootprintPlugin {
    let name = "SSHKeys"
    let description = "Same SSH public key on GitHub, GitLab and Codeberg accounts of this name"
    let accepts: Set<TargetShape> = [.username]
    let cacheTTL: TimeInterval = 86_400

    static let hosts: [(platform: String, host: String)] = [
        ("github", "github.com"), ("gitlab", "gitlab.com"), ("codeberg", "codeberg.org"),
    ]

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username.range(of: #"^[A-Za-z0-9]([A-Za-z0-9._-]{0,37}[A-Za-z0-9])?$"#, options: .regularExpression) != nil,
              username.range(of: #"^[0-9]+$"#, options: .regularExpression) == nil
        else { return [] }

        var keys: [String: [String]] = [:]
        for (platform, host) in Self.hosts {
            guard let url = URL(string: "https://\(host)/\(username).keys"),
                  let response = await PluginHTTP.request(
                    url, headers: ["Accept": "text/plain"], timeout: 10,
                    bodyMode: .complete(maxBytes: 64 * 1_024), on: app
                  ),
                  response.status == 200,
                  let text = String(bytes: response.data, encoding: .utf8) else { continue }
            keys[platform] = Self.fingerprints(in: text)
        }
        return Self.evaluate(username: username, keys: keys)
    }

    /// `SHA256:…` fingerprints (as `ssh-keygen -l` prints them) of the keys in
    /// an `authorized_keys`-style listing. Anything else, such as the HTML of
    /// a sign-in redirect, yields nothing.
    static func fingerprints(in listing: String) -> [String] {
        var seen: Set<String> = []
        return listing.split(whereSeparator: \.isNewline).prefix(50).compactMap { line -> String? in
            let fields = line.split(separator: " ")
            guard fields.count >= 2,
                  fields[0].hasPrefix("ssh-") || fields[0].hasPrefix("ecdsa-") || fields[0].hasPrefix("sk-"),
                  let blob = Data(base64Encoded: String(fields[1])), blob.count >= 32 else { return nil }
            let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
            let fingerprint = "SHA256:" + digest.replacingOccurrences(of: "=", with: "")
            return seen.insert(fingerprint).inserted ? fingerprint : nil
        }
    }

    /// One result per account that shares a key with another platform's
    /// account of the same name.
    static func evaluate(username: String, keys: [String: [String]]) -> [PluginResult] {
        let order = hosts.map(\.platform).filter { keys[$0] != nil }
        return order.compactMap { platform -> PluginResult? in
            let own = Set(keys[platform] ?? [])
            let sharing = order.filter { $0 != platform && !own.isDisjoint(with: keys[$0] ?? []) }
            guard !sharing.isEmpty else { return nil }
            let shared = own.intersection(sharing.flatMap { keys[$0] ?? [] }).sorted()
            let host = hosts.first { $0.platform == platform }?.host ?? platform
            let others = sharing.map { other in "\(hosts.first { $0.platform == other }?.host ?? other)/\(username)" }
            let raw = "The same SSH key (\(shared[0])\(shared.count > 1 ? " and \(shared.count - 1) more" : "")) "
                + "is on \(host)/\(username) and \(others.joined(separator: ", "))"
            return PluginResult(
                source: "SSH keys", type: "ssh_key_match", confidenceScore: 0.9, rawData: raw,
                metadata: ["platform": platform, "username": username,
                           "fingerprints": shared.prefix(5).joined(separator: ","),
                           "linked": IdentityLinks.linked(sharing.map { ($0, username) }) ?? "",
                           "linkKind": "observed",
                           "linkReason": "the same SSH public key is on both accounts"])
        }
    }
}
