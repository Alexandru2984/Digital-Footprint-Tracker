import Vapor
import Crypto

struct GravatarPlugin: FootprintPlugin {
    let name = "GravatarCheck"
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] } // Only process emails
        
        let cleanedEmail = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = Insecure.MD5.hash(data: Data(cleanedEmail.utf8))
        let hashString = digest.map { String(format: "%02hhx", $0) }.joined()
        
        let url = "https://en.gravatar.com/avatar/\(hashString)?d=404"
        
        do {
            let response = try await app.client.get(URI(string: url))
            
            if response.status == .ok {
                return [
                    PluginResult(
                        source: name,
                        type: "avatar_presence",
                        confidenceScore: 1.0,
                        rawData: "Gravatar found! URL: \(url)"
                    )
                ]
            } else {
                return []
            }
        } catch {
            return [
                PluginResult(
                    source: name,
                    type: "error",
                    confidenceScore: 0.0,
                    rawData: "Gravatar query failed."
                )
            ]
        }
    }
}
