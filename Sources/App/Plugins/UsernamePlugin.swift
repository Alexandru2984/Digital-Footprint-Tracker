import Vapor

struct UsernamePlugin: FootprintPlugin {
    let name = "UsernamePatternCheck"
    
    func scan(input: String, on req: Request) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] } // Only process usernames
        
        let isValidPattern = input.range(of: "^[a-zA-Z0-9_-]{3,16}$", options: .regularExpression) != nil
        
        return [
            PluginResult(
                source: name,
                type: "username_validation",
                confidenceScore: 1.0,
                rawData: "Username is valid: \(isValidPattern)"
            )
        ]
    }
}
