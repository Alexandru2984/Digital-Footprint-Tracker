import Vapor

struct SherlockSite: Decodable {
    let errorType: String
    let url: String
    let urlMain: String
    let errorMsg: StringOrArray?
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
        let filePath = "/home/micu/swift+vapor/Sources/App/Plugins/sherlock_data.json"
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
            let decoded = try JSONDecoder().decode(SherlockData.self, from: data)
            self.sites = decoded.sites
            print("Loaded \(self.sites.count) OSINT sites from Sherlock data.")
        } catch {
            print("Failed to load Sherlock data: \(error)")
            self.sites = [:]
        }
    }
    
    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)
        
        var validSites: [(String, SherlockSite)] = []
        for (siteName, siteData) in sites {
            validSites.append((siteName, siteData))
        }
        
        let concurrencyLimit = 30 // 30 concurrent requests
        var results: [PluginResult] = []
        
        // Setup shared HTTP client configs (like User-Agent)
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        
        // Chunk processing to avoid overwhelming memory/connections
        for chunk in validSites.chunked(into: concurrencyLimit) {
            let chunkResults = await withTaskGroup(of: PluginResult?.self) { group in
                for (siteName, siteData) in chunk {
                    group.addTask {
                        let targetURL = siteData.url.replacingOccurrences(of: "{}", with: username)
                        let uri = URI(string: targetURL)
                        
                        do {
                            // Some sites block without proper headers
                            var headers = HTTPHeaders()
                            headers.add(name: .userAgent, value: userAgent)
                            headers.add(name: .accept, value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                            headers.add(name: .acceptLanguage, value: "en-US,en;q=0.5")
                            
                            let response = try await app.client.get(uri, headers: headers)
                            
                            if siteData.errorType == "status_code" {
                                if response.status == .ok || response.status.code == 200 {
                                    // Found!
                                    return PluginResult(source: siteName, type: "account_presence", confidenceScore: 1.0, rawData: "Account found! Profile: \(targetURL)")
                                }
                            } else if siteData.errorType == "message" {
                                if response.status == .ok {
                                    if let body = response.body {
                                        let html = String(buffer: body)
                                        var notFound = false
                                        if let errorMsg = siteData.errorMsg {
                                            switch errorMsg {
                                            case .string(let s):
                                                if html.contains(s) { notFound = true }
                                            case .array(let a):
                                                for s in a {
                                                    if html.contains(s) { notFound = true; break }
                                                }
                                            }
                                        }
                                        if !notFound {
                                            return PluginResult(source: siteName, type: "account_presence", confidenceScore: 0.9, rawData: "Account found (message-based)! Profile: \(targetURL)")
                                        }
                                    }
                                }
                            }
                            // response_url not implemented for simplicity
                            return nil
                        } catch {
                            return nil
                        }
                    }
                }
                
                var collected: [PluginResult] = []
                for await res in group {
                    if let validRes = res {
                        collected.append(validRes)
                    }
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
