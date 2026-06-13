import Vapor
import Foundation

struct BulkEmailPlugin: FootprintPlugin {
    let name = "BulkEmailOSINT"
    let description = "Email-to-account correlation (Holehe)"
    let cacheTTL: TimeInterval = 86_400 // 24 h
    
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
        // Per-invocation HOME directory with 0700 perms — previously set to
        // /tmp, which is world-readable/writable. Anything holehe wrote to
        // $HOME (config, cache, cookies) was accessible to every local user
        // on the box. The dir is removed after the subprocess exits.
        let processHome = NSTemporaryDirectory() + "holehe-\(UUID().uuidString)"
        do {
            try FileManager.default.createDirectory(
                atPath: processHome,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
        } catch {
            app.logger.warning("Holehe: failed to create per-process HOME (\(error)); skipping")
            return []
        }
        defer { try? FileManager.default.removeItem(atPath: processHome) }

        // Explicitly clear the environment so holehe cannot access app secrets.
        let pythonPath = Environment.get("HOLEHE_PYTHONPATH") ?? "/home/micu/.local/lib/python3.12/site-packages"
        process.environment = [
            "PATH": "/usr/bin:/usr/local/bin:/home/micu/.local/bin",
            "HOME": processHome,
            "PYTHONPATH": pythonPath
        ]

        let pipe = Pipe()
        process.standardOutput = pipe
        // Discard tqdm/progress output; never read this pipe to avoid a buffer-full hang.
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            // waitUntilExit() is a blocking call; wrap it on a dedicated OS thread
            // so we never block a Swift cooperative-pool thread.
            // A 60-second hard kill ensures the process cannot hang indefinitely:
            // the terminationHandler fires the semaphore whether it exits normally
            // or is killed by the timer.
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let sema = DispatchSemaphore(value: 0)
                process.terminationHandler = { _ in sema.signal() }

                // Kill after 60 s on a background queue — independent of Swift concurrency.
                let killTimer = DispatchWorkItem {
                    if process.isRunning {
                        process.terminate()
                    }
                }
                DispatchQueue.global(qos: .utility).asyncAfter(
                    deadline: .now() + 60,
                    execute: killTimer
                )

                DispatchQueue.global(qos: .utility).async {
                    sema.wait()
                    killTimer.cancel()
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
                            rawData: "Account registered with email on \(site) (detected via recovery flow)",
                            metadata: ["email": cleanedEmail, "platform": site]
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
