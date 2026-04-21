import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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

    // Load JSON into memory
    private let sites: [String: SherlockSite]

    init() {
        let envPath = Environment.get("SHERLOCK_DATA_PATH")
        let cwdPath = FileManager.default.currentDirectoryPath + "/Sources/App/Plugins/sherlock_data.json"
        let filePath = envPath ?? cwdPath
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
            let decoded = try JSONDecoder().decode(SherlockData.self, from: data)
            self.sites = decoded.sites
            print("Loaded \(self.sites.count) OSINT sites from Sherlock data at \(filePath).")
        } catch {
            print("Failed to load Sherlock data from \(filePath): \(error)")
            self.sites = [:]
        }
    }
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)

        let validSites = Array(sites)
        let concurrencyLimit = 30
        var results: [PluginResult] = []
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        // URLSession for response_url sites: follows redirects and exposes the
        // final URL, which is what Sherlock's response_url errorType checks.
        // Using Foundation's URLSession keeps this independent of the Vapor/NIO
        // lifecycle — avoids crashes when the test app shuts down mid-scan.
        let urlSession: URLSession = {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 10
            cfg.timeoutIntervalForResource = 12
            return URLSession(configuration: cfg)
        }()

        for chunk in validSites.chunked(into: concurrencyLimit) {
            let chunkResults = await withTaskGroup(of: PluginResult?.self) { group in
                for (siteName, siteData) in chunk {
                    group.addTask {
                        let targetURL = siteData.url.replacingOccurrences(of: "{}", with: username)

                        do {
                            if siteData.errorType == "response_url" {
                                guard let errorURL = siteData.errorUrl, !errorURL.isEmpty,
                                      let url = URL(string: targetURL) else { return nil }
                                var req = URLRequest(url: url, timeoutInterval: 10)
                                req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
                                let (_, resp) = try await urlSession.data(for: req)
                                guard let http = resp as? HTTPURLResponse else { return nil }
                                let finalURL = http.url?.absoluteString ?? targetURL
                                let errTrim = errorURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                                let finalTrim = finalURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                                if finalTrim.hasPrefix(errTrim) { return nil }
                                return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.8, rawData: "Account found (redirect-based). Profile: \(targetURL)")
                            }

                            guard let url = URL(string: targetURL) else { return nil }
                            var urlReq = URLRequest(url: url, timeoutInterval: 10)
                            urlReq.setValue(userAgent, forHTTPHeaderField: "User-Agent")
                            urlReq.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", forHTTPHeaderField: "Accept")
                            urlReq.setValue("en-US,en;q=0.5", forHTTPHeaderField: "Accept-Language")

                            let (data, resp) = try await urlSession.data(for: urlReq)
                            guard let http = resp as? HTTPURLResponse else { return nil }

                            if siteData.errorType == "status_code" {
                                if http.statusCode == 200 {
                                    return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.5, rawData: "Account possibly found (HTTP 200). Profile: \(targetURL)")
                                }
                            } else if siteData.errorType == "message" {
                                if http.statusCode == 200 {
                                    guard data.count <= 512 * 1024 else { return nil }
                                    let html = String(decoding: data, as: UTF8.self)
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
                                        return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.9, rawData: "Account found (message-based)! Profile: \(targetURL)")
                                    }
                                }
                            }
                            return nil
                        } catch {
                            return nil
                        }
                    }
                }

                var collected: [PluginResult] = []
                for await res in group {
                    if let r = res { collected.append(r) }
                }
                return collected
            }
            results.append(contentsOf: chunkResults)
        }

        return results
    }
}

// Helper extension for chunking arrays
extension Array {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}
