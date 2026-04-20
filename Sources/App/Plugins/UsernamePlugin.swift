import Vapor

struct UsernamePlugin: FootprintPlugin {
    let name = "GitHubAccountCheck"
    
    func scan(input: String, on req: Request) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] } // Only process usernames
        
        let cleanedUsername = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanedUsername.range(of: "^[a-zA-Z0-9_-]{1,39}$", options: .regularExpression) != nil else {
            return [
                PluginResult(
                    source: name,
                    type: "username_validation",
                    confidenceScore: 0.0,
                    rawData: "Invalid GitHub username format."
                )
            ]
        }
        
        let url = "https://api.github.com/users/\(cleanedUsername)"
        
        do {
            let response = try await req.client.get(URI(string: url), headers: ["User-Agent": "Digital-Footprint-Tracker/1.0"])
            
            if response.status == .ok {
                // Return found!
                // Try parsing JSON to extract URL
                struct GitHubUser: Content {
                    let html_url: String
                    let public_repos: Int?
                }
                
                var dataStr = "Account found on GitHub! Profile: https://github.com/\(cleanedUsername)"
                if let user = try? response.content.decode(GitHubUser.self) {
                    dataStr += " | Repos: \(user.public_repos ?? 0)"
                }
                
                return [
                    PluginResult(
                        source: name,
                        type: "account_presence",
                        confidenceScore: 1.0,
                        rawData: dataStr
                    )
                ]
            } else if response.status == .notFound {
                return [
                    PluginResult(
                        source: name,
                        type: "account_presence",
                        confidenceScore: 0.0,
                        rawData: "No GitHub account found for this username."
                    )
                ]
            } else {
                return [
                    PluginResult(
                        source: name,
                        type: "api_rate_limit",
                        confidenceScore: 0.5,
                        rawData: "GitHub API limit reached or returned status: \(response.status)"
                    )
                ]
            }
        } catch {
             return [
                 PluginResult(
                     source: name,
                     type: "error",
                     confidenceScore: 0.0,
                     rawData: "Failed to query GitHub: \(error.localizedDescription)"
                 )
             ]
         }
    }
}
