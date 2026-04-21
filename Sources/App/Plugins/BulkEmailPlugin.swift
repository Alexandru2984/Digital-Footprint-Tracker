import Vapor
import Foundation

struct BulkEmailPlugin: FootprintPlugin {
    let name = "BulkEmailOSINT"
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }
        
        let cleanedEmail = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        
        // Simple regex for email safety to prevent shell injection (just in case)
        guard cleanedEmail.range(of: "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,64}$", options: .regularExpression) != nil else {
            return []
        }
        
        // Execute holehe CLI
        let holehePath = Environment.get("HOLEHE_PATH") ?? "/usr/local/bin/holehe"
        guard FileManager.default.isExecutableFile(atPath: holehePath) else {
            app.logger.warning("holehe binary not found at \(holehePath); set HOLEHE_PATH env var")
            return []
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: holehePath)
        process.arguments = [cleanedEmail, "--only-used", "--no-color"]
        // Explicitly clear the environment so holehe cannot access app secrets
        // (DATABASE_PASSWORD, HIBP_API_KEY, etc.) inherited from the parent process.
        process.environment = ["PATH": "/usr/bin:/usr/local/bin:/home/micu/.local/bin", "HOME": "/tmp"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe() // Ignore stderr (tqdm progress bars go to stderr usually)

        do {
            try process.run()
            // waitUntilExit() is a blocking call. Running it inside
            // withCheckedContinuation on a detached task avoids blocking
            // a thread from the Swift concurrency cooperative thread pool.
            await withCheckedContinuation { continuation in
                Task.detached(priority: .utility) {
                    process.waitUntilExit()
                    continuation.resume()
                }
            }

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else {
                return []
            }
            
            var results: [PluginResult] = []
            let lines = output.components(separatedBy: .newlines)
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("[+] ") {
                    let site = trimmed.replacingOccurrences(of: "[+] ", with: "")
                    
                    // Skip the legend line printed by holehe
                    if site.contains("Email used,") || site.contains("Email not used,") { continue }
                    
                    results.append(
                        PluginResult(
                            source: site,
                            type: "account_presence",
                            confidenceScore: 1.0,
                            rawData: "Account registered with email on \(site) (detected via recovery flow)"
                        )
                    )
                }
            }
            
            return results
        } catch {
            app.logger.error("Holehe execution failed: \(error)")
            return []
        }
    }
}
