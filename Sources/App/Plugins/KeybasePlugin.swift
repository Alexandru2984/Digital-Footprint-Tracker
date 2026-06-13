import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Looks up a Keybase username and extracts cross-platform identity proofs.
///
/// Keybase is an identity verification platform — users can cryptographically
/// prove they own accounts on GitHub, Twitter, Reddit, HackerNews, etc.
/// This makes it an extremely high-value OSINT source for linking identities.
///
/// API: https://keybase.io/_/api/1.0/user/lookup.json (public, no key needed)
/// Uses URLSession — lifecycle-independent, safe from asyncShutdown races.
struct KeybasePlugin: FootprintPlugin {
    let name = "KeybaseOSINT"
    let description = "Keybase identity lookup (cross-platform proofs)"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@"),
              input.range(of: #"^\+?[0-9]{7,15}$"#, options: .regularExpression) == nil,
              input.range(of: #"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"#,
                          options: .regularExpression) == nil
        else { return [] }

        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Keybase usernames: lowercase letters, digits, underscores, 2-16 chars
        guard username.count >= 2, username.count <= 16,
              username.range(of: #"^[a-zA-Z0-9_]+$"#, options: .regularExpression) != nil
        else { return [] }

        guard let url = URL(string: "https://keybase.io/_/api/1.0/user/lookup.json?usernames=\(username.lowercased())") else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 12)
        req.setValue("DigitalFootprintTracker/1.0 (OSINT research tool)", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return [] }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let status = json["status"] as? [String: Any],
                  status["name"] as? String == "OK",
                  let them = json["them"] as? [[String: Any]],
                  let user = them.first, !user.isEmpty
            else { return [] }

            var results: [PluginResult] = []

            // Basic profile
            let profile = user["profile"] as? [String: Any]
            let fullName  = profile?["full_name"] as? String ?? ""
            let location  = profile?["location"]  as? String ?? ""
            let bio       = profile?["bio"]        as? String ?? ""

            var profileParts = ["Keybase profile found: keybase.io/\(username.lowercased())"]
            if !fullName.isEmpty  { profileParts.append("Name: \(fullName)") }
            if !location.isEmpty  { profileParts.append("Location: \(location)") }
            if !bio.isEmpty {
                let truncBio = bio.count > 100 ? String(bio.prefix(100)) + "…" : bio
                profileParts.append("Bio: \(truncBio)")
            }

            results.append(PluginResult(
                source: "Keybase",
                type: "account_presence",
                confidenceScore: 1.0,
                rawData: profileParts.joined(separator: " | ")
            ))

            // Cross-platform identity proofs — the OSINT gold
            if let proofsSummary = user["proofs_summary"] as? [String: Any],
               let allProofs = proofsSummary["all"] as? [[String: Any]], !allProofs.isEmpty {

                var proofLines: [String] = []
                for proof in allProofs {
                    let proofType    = proof["proof_type"] as? String ?? "unknown"
                    let nametxt      = proof["nametxt"]    as? String ?? ""
                    let serviceURL   = proof["service_url"] as? String ?? ""
                    if !nametxt.isEmpty {
                        let line = serviceURL.isEmpty
                            ? "\(proofType): \(nametxt)"
                            : "\(proofType): \(nametxt) (\(serviceURL))"
                        proofLines.append(line)
                    }
                }

                if !proofLines.isEmpty {
                    results.append(PluginResult(
                        source: "Keybase",
                        type: "identity_proof",
                        confidenceScore: 0.98,
                        rawData: "Keybase identity proofs for \(username): \(proofLines.joined(separator: " | "))"
                    ))
                }
            }

            // Cryptocurrency wallets (if any)
            if let cryptocurrency = user["cryptocurrency_addresses"] as? [String: Any],
               !cryptocurrency.isEmpty {
                var walletParts: [String] = []
                for (coin, addrs) in cryptocurrency {
                    if let addrList = addrs as? [[String: Any]] {
                        for addr in addrList {
                            if let address = addr["address"] as? String {
                                walletParts.append("\(coin.uppercased()): \(address)")
                            }
                        }
                    }
                }
                if !walletParts.isEmpty {
                    results.append(PluginResult(
                        source: "Keybase",
                        type: "crypto_wallet",
                        confidenceScore: 0.99,
                        rawData: "Cryptocurrency addresses linked to \(username): \(walletParts.joined(separator: " | "))"
                    ))
                }
            }

            return results
        } catch {
            return []
        }
    }
}
