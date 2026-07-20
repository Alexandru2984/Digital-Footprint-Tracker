import Vapor
import Foundation

struct BulkEmailPlugin: FootprintPlugin {
    let name = "BulkEmailOSINT"
    let description = "Email-to-account correlation (Holehe)"
    let cacheTTL: TimeInterval = 86_400 // 24 h
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }
        
        guard let cleanedEmail = EmailAddress.normalize(input) else { return [] }
        
        // Execute holehe CLI
        let holehePath = Environment.get("HOLEHE_PATH") ?? "/usr/local/bin/holehe"
        guard FileManager.default.isExecutableFile(atPath: holehePath) else {
            app.logger.warning("holehe binary not found at \(holehePath); set HOLEHE_PATH env var")
            return []
        }
        var processEnvironment = [
            "PATH": "/usr/bin:/usr/local/bin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
        ]
        if let pythonPath = Environment.get("HOLEHE_PYTHONPATH"), !pythonPath.isEmpty {
            processEnvironment["PYTHONPATH"] = pythonPath
        }

        do {
            let execution = try await BoundedProcess.run(
                executable: holehePath,
                arguments: [cleanedEmail, "--only-used", "--no-color"],
                environment: processEnvironment,
                timeout: 60,
                maxOutputBytes: 1 * 1_024 * 1_024
            )
            guard execution.succeeded,
                  let output = String(data: execution.stdout, encoding: .utf8) else { return [] }
            
            var results: [PluginResult] = []
            let lines = output.components(separatedBy: .newlines)
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("[+] ") {
                    let rawSite = String(trimmed.dropFirst(4))
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    
                    // Skip the legend line printed by holehe
                    if rawSite.contains("Email used,") || rawSite.contains("Email not used,") { continue }
                    guard !rawSite.isEmpty, rawSite.utf8.count <= 120,
                          rawSite.unicodeScalars.allSatisfy({
                            !CharacterSet.controlCharacters.contains($0)
                          }) else { continue }
                    let site = String(rawSite.prefix(100))
                    
                    results.append(
                        PluginResult(
                            source: site,
                            type: "account_presence",
                            confidenceScore: 1.0,
                            rawData: "Account registered with email on \(site) (detected via recovery flow)",
                            metadata: ["email": cleanedEmail, "platform": site]
                        )
                    )
                }
            }
            
            return results
        } catch {
            app.logger.error("Holehe execution could not be started.")
            return []
        }
    }
}
