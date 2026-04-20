import Vapor

struct GravatarPlugin: FootprintPlugin {
    let name = "GravatarCheck"
    
    func scan(input: String, on req: Request) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] } // Only process emails
        
        // Basic check just by constructing a URL.
        // A real plugin would hash the email and check Gravatar.
        return [
            PluginResult(
                source: name,
                type: "avatar_presence",
                confidenceScore: 0.9,
                rawData: "Email formatted input detected, gravatar lookup simulated."
            )
        ]
    }
}
