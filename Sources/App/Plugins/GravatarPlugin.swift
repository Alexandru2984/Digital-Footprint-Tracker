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
    let description = "Gravatar profile picture lookup by email"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }

        let cleanedEmail = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = Insecure.MD5.hash(data: Data(cleanedEmail.utf8))
        let hashString = digest.map { String(format: "%02hhx", $0) }.joined()

        let urlString = "https://en.gravatar.com/avatar/\(hashString)?d=404"
        guard let url = URL(string: urlString) else { return [] }

        // HEAD is enough to detect presence (d=404 makes a missing avatar 404);
        // avoids downloading the image bytes just to check a status code.
        guard let resp = await PluginHTTP.request(url, method: "HEAD"), resp.status == 200 else { return [] }
        return [PluginResult(
            source: name,
            type: "avatar_presence",
            confidenceScore: 1.0,
            rawData: "Gravatar found! URL: \(urlString)",
            metadata: ["email": cleanedEmail, "profileURL": urlString]
        )]
    }
}
