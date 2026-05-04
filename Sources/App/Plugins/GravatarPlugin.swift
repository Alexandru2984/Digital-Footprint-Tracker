import Vapor
import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Uses URLSession (Foundation) so it is independent of the Vapor/NIO lifecycle
/// and safe to call from background tasks that may outlive the app in tests.
struct GravatarPlugin: FootprintPlugin {
    let name = "GravatarCheck"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        let cleanedEmail = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = Insecure.MD5.hash(data: Data(cleanedEmail.utf8))
        let hashString = digest.map { String(format: "%02hhx", $0) }.joined()

        let urlString = "https://en.gravatar.com/avatar/\(hashString)?d=404"
        guard let url = URL(string: urlString) else { return [] }

        var req = URLRequest(url: url, timeoutInterval: 10)
        req.setValue("DigitalFootprintTracker/1.0", forHTTPHeaderField: "User-Agent")

        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { return [] }
            if http.statusCode == 200 {
                return [PluginResult(
                    source: name,
                    type: "avatar_presence",
                    confidenceScore: 1.0,
                    rawData: "Gravatar found! URL: \(urlString)"
                )]
            }
            return []
        } catch {
            return []
        }
    }
}
