import Vapor
import Foundation
import Logging

/// File-scoped logger so `init()` (which has no `Application` reference) can
/// emit structured log events to the same backend as the rest of the app
/// instead of plain `print()` to stdout.
private let pluginLogger = Logger(label: "app.plugin.bulkusername")

struct SherlockSite: Decodable {
    let errorType: String
    let url: String
    let urlMain: String
    let errorMsg: StringOrArray?
    let errorUrl: String?
    let regexCheck: String?

    // Custom decodable to handle errorMsg which can be a String or Array of Strings in the Sherlock data
    enum StringOrArray: Decodable {
        case string(String)
        case array([String])

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let str = try? container.decode(String.self) {
                self = .string(str)
            } else if let arr = try? container.decode([String].self) {
                self = .array(arr)
            } else {
                throw DecodingError.typeMismatch(StringOrArray.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Not a string or array"))
            }
        }
    }
}

// Sherlock data wrapper
struct SherlockData: Decodable {
    let schema: String?
    // Exclude $schema, keep the rest as dictionary
    let sites: [String: SherlockSite]
    
    // Custom decoding to bypass $schema
    private struct DynamicKey: CodingKey {
        var stringValue: String
        init?(stringValue: String) { self.stringValue = stringValue }
        var intValue: Int? { return nil }
        init?(intValue: Int) { return nil }
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: DynamicKey.self)
        var tempSites = [String: SherlockSite]()
        var s: String? = nil
        for key in container.allKeys {
            if key.stringValue == "$schema" {
                s = try? container.decode(String.self, forKey: key)
            } else {
                if let site = try? container.decode(SherlockSite.self, forKey: key) {
                    tempSites[key.stringValue] = site
                }
            }
        }
        self.schema = s
        self.sites = tempSites
    }
}

struct BulkUsernamePlugin: FootprintPlugin {
    let name = "BulkOSINT"
    let description = "Username presence across 480+ platforms (Sherlock)"
    let cacheTTL: TimeInterval = 21_600 // 6 h — accounts churn but mostly persist
    let heavy = true // 480 outbound requests per run — bound fan-out to one candidate

    // Load JSON into memory
    private let sites: [String: SherlockSite]

    init() {
        let envPath = Environment.get("SHERLOCK_DATA_PATH")
        let bundledPath = Bundle.module.url(forResource: "sherlock_data", withExtension: "json")?.path
        let cwdPath = FileManager.default.currentDirectoryPath + "/Sources/App/Plugins/sherlock_data.json"
        let filePath = envPath ?? bundledPath ?? cwdPath
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
            let decoded = try JSONDecoder().decode(SherlockData.self, from: data)
            self.sites = decoded.sites
            pluginLogger.info("Loaded \(self.sites.count) OSINT sites from Sherlock data at \(filePath).")
        } catch {
            pluginLogger.error("Failed to load Sherlock data from \(filePath): \(error)")
            self.sites = [:]
        }
    }
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)

        let validSites = Array(sites)
        let maxConcurrent = 30
        // Internal time budget kept under ScanPluginRunner's 120s hard deadline.
        // Previously this ran 480 sites in sequential chunks of 30 and returned
        // everything only at the very end — a slow run blew past 120s, got
        // hard-cancelled, and lost ALL its findings. Now it keeps a sliding
        // window of in-flight requests (no head-of-line blocking on the slowest
        // site in a chunk) and stops starting new ones once the budget elapses,
        // returning whatever it has found so far.
        let deadline = Date().addingTimeInterval(85)
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        var results: [PluginResult] = []
        var checked = 0
        var iterator = validSites.makeIterator()

        await withTaskGroup(of: PluginResult?.self) { group in
            // Seed the sliding window.
            var scheduled = 0
            while scheduled < maxConcurrent, let (siteName, siteData) = iterator.next() {
                group.addTask { await Self.checkSite(siteName, siteData, username: username, app: app, userAgent: userAgent) }
                scheduled += 1
            }
            // Drain results and top up the window until the site list is
            // exhausted or the time budget runs out.
            for await res in group {
                checked += 1
                if let pr = res { results.append(pr) }
                if Date() < deadline, !Task.isCancelled,
                   let (siteName, siteData) = iterator.next() {
                    group.addTask { await Self.checkSite(siteName, siteData, username: username, app: app, userAgent: userAgent) }
                }
            }
        }

        if checked < validSites.count {
            pluginLogger.info("BulkUsername: checked \(checked)/\(validSites.count) sites before the 85s budget elapsed.")
        }
        return results
    }

    /// Checks a single Sherlock site for the username. Returns a hit or nil.
    /// Static so the sliding-window task group can call it without capturing
    /// `self`, and so the per-site logic lives in one testable place.
    private static func checkSite(
        _ siteName: String,
        _ siteData: SherlockSite,
        username: String,
        app: Application,
        userAgent: String
    ) async -> PluginResult? {
        let targetURL = siteData.url.replacingOccurrences(of: "{}", with: username)
        do {
            if siteData.errorType == "response_url" {
                guard let errorURL = siteData.errorUrl, !errorURL.isEmpty,
                      let url = URL(string: targetURL)
                else { return nil }
                let response = try await OutboundHTTP.request(
                    url,
                    headers: ["User-Agent": userAgent],
                    timeout: 10,
                    bodyMode: .prefix(maxBytes: 0),
                    maxRedirects: 3,
                    on: app
                )
                let finalURL = response.finalURL.absoluteString
                let errTrim = errorURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                let finalTrim = finalURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                if finalTrim.hasPrefix(errTrim) { return nil }
                return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.8,
                                    rawData: "Account found (redirect-based). Profile: \(targetURL)",
                                    metadata: ["platform": siteName, "username": username, "profileURL": targetURL])
            }

            guard let url = URL(string: targetURL) else { return nil }
            let needsMessageBody = siteData.errorType == "message"
            let response = try await OutboundHTTP.request(
                url,
                headers: [
                    "User-Agent": userAgent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                ],
                timeout: 10,
                bodyMode: needsMessageBody ? .complete(maxBytes: 512 * 1_024) : .prefix(maxBytes: 0),
                maxRedirects: 3,
                on: app
            )

            if siteData.errorType == "status_code" {
                if response.status == 200 {
                    return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.5,
                                        rawData: "Account possibly found (HTTP 200). Profile: \(targetURL)",
                                        metadata: ["platform": siteName, "username": username, "profileURL": targetURL])
                }
            } else if siteData.errorType == "message" {
                if response.status == 200 {
                    let html = String(decoding: response.data, as: UTF8.self)
                    var notFound = false
                    if let errorMsg = siteData.errorMsg {
                        switch errorMsg {
                        case .string(let s):
                            if html.contains(s) { notFound = true }
                        case .array(let a):
                            for s in a where html.contains(s) { notFound = true; break }
                        }
                    }
                    if !notFound {
                        return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.9,
                                            rawData: "Account found (message-based)! Profile: \(targetURL)",
                                            metadata: ["platform": siteName, "username": username, "profileURL": targetURL])
                    }
                }
            }
            return nil
        } catch {
            return nil
        }
    }
}
