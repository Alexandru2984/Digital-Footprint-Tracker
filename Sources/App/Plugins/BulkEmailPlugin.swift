import Vapor
import Foundation

struct BulkEmailPlugin: FootprintPlugin {
    let name = "BulkEmailOSINT"
    let description = "Email-to-account correlation (Holehe)"
    /// holehe enumerates account registrations for an email.
    let accepts: Set<TargetShape> = [.email]
    let cacheTTL: TimeInterval = 86_400 // 24 h
    /// v2: a module's extra detail is no longer read as part of the site name.
    /// v3: each account is a node tied to the address.
    let cacheVersion = 3
    
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
                // `--` ends options: a target must never be readable as a flag, whatever
                // the validators upstream happen to guarantee today.
                arguments: ["--only-used", "--no-color", "--", cleanedEmail],
                environment: processEnvironment,
                timeout: 60,
                maxOutputBytes: 1 * 1_024 * 1_024
            )
            guard execution.succeeded,
                  let output = String(data: execution.stdout, encoding: .utf8) else { return [] }
            
            return Self.parse(output: output, email: cleanedEmail)
        } catch {
            app.logger.error("Holehe execution could not be started.")
            return []
        }
    }

    /// One result per `[+] site` line of holehe's output. Some modules add
    /// what they read after the site (`[+] en.gravatar.com / FullName x / url`):
    /// the site is the first part, the rest is detail.
    static func parse(output: String, email: String) -> [PluginResult] {
        var results: [PluginResult] = []
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("[+] ") else { continue }
            let rest = String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespacesAndNewlines)
            // Skip the legend line printed by holehe
            if rest.contains("Email used,") || rest.contains("Email not used,") { continue }
            guard rest.utf8.count <= 300,
                  rest.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else { continue }
            let parts = rest.components(separatedBy: " / ").map { $0.trimmingCharacters(in: .whitespaces) }
            let site = parts[0].lowercased()
            guard site.range(of: #"^[a-z0-9][a-z0-9.-]{0,98}[a-z0-9]$"#, options: .regularExpression) != nil,
                  !results.contains(where: { $0.source == site }) else { continue }
            var raw = "Account registered with email on \(site) (detected via recovery flow)"
            if parts.count > 1 { raw += " | " + parts.dropFirst().prefix(4).joined(separator: " | ") }
            results.append(PluginResult(source: site, type: "account_presence", confidenceScore: 1.0, rawData: raw,
                                        // `account`: the site's account for this address, so
                                        // it is a node in the connections, tied to the address.
                                        metadata: ["email": email, "platform": site, "account": email,
                                                   "matchKind": "observed",
                                                   "matchReason": "the site's account recovery recognises this address"]))
        }
        return results
    }
}
