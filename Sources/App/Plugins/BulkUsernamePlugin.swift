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
    /// Where to ask instead of the profile page (an API that answers plainly),
    /// how, and with what: the profile page stays the link shown.
    var urlProbe: String? = nil
    var headers: [String: String]? = nil
    var request_method: String? = nil
    var request_payload: Payload? = nil
    /// Statuses that mean "no such user" for a `status_code` site.
    var errorCode: StatusCodes? = nil

    /// A request body template: any JSON, `{}` in its strings is the name.
    indirect enum Payload: Codable, Equatable {
        case string(String), number(Double), bool(Bool), null
        case array([Payload]), object([String: Payload])

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if container.decodeNil() { self = .null }
            else if let value = try? container.decode(Bool.self) { self = .bool(value) }
            else if let value = try? container.decode(Double.self) { self = .number(value) }
            else if let value = try? container.decode(String.self) { self = .string(value) }
            else if let value = try? container.decode([Payload].self) { self = .array(value) }
            else { self = .object(try container.decode([String: Payload].self)) }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .bool(let value): try container.encode(value)
            case .null: try container.encodeNil()
            case .array(let value): try container.encode(value)
            case .object(let value): try container.encode(value)
            }
        }

        func filled(with name: String) -> Payload {
            switch self {
            case .string(let value): return .string(value.replacingOccurrences(of: "{}", with: name))
            case .array(let value): return .array(value.map { $0.filled(with: name) })
            case .object(let value): return .object(value.mapValues { $0.filled(with: name) })
            default: return self
            }
        }
    }

    struct StatusCodes: Decodable, Equatable {
        let codes: [Int]
        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let list = try? container.decode([Int].self) { codes = list } else { codes = [try container.decode(Int.self)] }
        }
    }

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
        var s: String?
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

extension SherlockSite {
    /// What to send for `name`: the probe URL when the site has one, its
    /// method, headers and body.
    func request(for name: String) -> (url: String, method: HTTPMethod, headers: [String: String], body: Data?) {
        let url = (urlProbe ?? self.url).replacingOccurrences(of: "{}", with: name)
        let method: HTTPMethod = switch request_method?.uppercased() {
        case "POST": .POST
        case "HEAD": .HEAD
        case "PUT": .PUT
        default: .GET
        }
        let body = request_payload.flatMap { try? JSONEncoder().encode($0.filled(with: name)) }
        var headers = headers ?? [:]
        if body != nil, !headers.keys.contains(where: { $0.lowercased() == "content-type" }) {
            headers["Content-Type"] = "application/json"
        }
        return (url, method, headers, body)
    }

    /// Whether `name` fits the site's own username rule, when it has one.
    func accepts(_ name: String) -> Bool {
        guard let rule = regexCheck, !rule.isEmpty else { return true }
        return name.range(of: rule, options: .regularExpression) != nil
    }
}

/// Which Sherlock sites can tell a real account from a missing one, learned by
/// asking them about a name nobody has. Process-local; a day's verdict.
actor SherlockReliability {
    static let shared = SherlockReliability()
    static let validity: TimeInterval = 86_400
    private var verdicts: [String: (reliable: Bool, at: Date)] = [:]

    func verdict(for site: String, now: Date = Date()) -> Bool? {
        guard let entry = verdicts[site], now.timeIntervalSince(entry.at) < Self.validity else { return nil }
        return entry.reliable
    }

    func record(_ site: String, reliable: Bool, at: Date = Date()) {
        verdicts[site] = (reliable, at)
    }

    func reset() { verdicts.removeAll() }

    /// Twelve random lowercase letters: valid almost everywhere, owned by no one.
    static func controlName() -> String {
        String((0..<12).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
    }
}

struct BulkUsernamePlugin: FootprintPlugin {
    let name = "BulkOSINT"
    let description = "Username presence across 480+ platforms (Sherlock)"
    /// 480 handle probes — never worth firing at a domain or an IP.
    let accepts: Set<TargetShape> = [.username]
    let cacheTTL: TimeInterval = 21_600 // 6 h — accounts churn but mostly persist
    /// v2: hits from sites that also "find" a name nobody has are dropped.
    /// v3: platforms a dedicated plugin checks are left to it.
    let cacheVersion = 5
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
    
    /// Platforms a dedicated plugin already checks for a username, by their
    /// canonical name: its answer is more precise (an API, not a status
    /// code), and a second, weaker hit for the same account is noise.
    static let dedicatedPlatforms: Set<String> = [
        "bluesky", "codeberg", "crates.io", "devto", "dockerhub", "duolingo", "github", "gitlab", "hackernews",
        "keybase", "lichess", "lobsters", "mastodon", "npm", "pypi", "speedrun", "steam", "telegram",
    ]

    static func checkedElsewhere(_ site: String) -> Bool {
        dedicatedPlatforms.contains(IdentityLinks.canonicalPlatform(site))
    }

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard !input.contains("@") else { return [] }
        let username = input.trimmingCharacters(in: .whitespacesAndNewlines)

        let validSites = sites.filter { !Self.checkedElsewhere($0.key) }
        let maxConcurrent = 30
        // Internal time budget kept under ScanPluginRunner's 120s hard deadline.
        // Previously this ran 480 sites in sequential chunks of 30 and returned
        // everything only at the very end — a slow run blew past 120s, got
        // hard-cancelled, and lost ALL its findings. Now it keeps a sliding
        // window of in-flight requests (no head-of-line blocking on the slowest
        // site in a chunk) and stops starting new ones once the budget elapses,
        // returning whatever it has found so far.
        let deadline = Date().addingTimeInterval(65)
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
            pluginLogger.info("BulkUsername: checked \(checked)/\(validSites.count) sites before the 65s budget elapsed.")
        }
        return await Self.dropUnreliable(results, sites: sites, app: app, userAgent: userAgent)
    }

    /// Asks every site that reported a hit about a name nobody has. A site
    /// that "finds" that one too answers yes to anything (a login wall, a
    /// catch-all page served with 200), so its hit says nothing and is
    /// dropped. Verdicts are kept for a day, so this costs a few dozen
    /// requests on the first scan and almost none after.
    static func dropUnreliable(
        _ hits: [PluginResult], sites: [String: SherlockSite], app: Application, userAgent: String
    ) async -> [PluginResult] {
        let control = SherlockReliability.controlName()
        var unchecked: [(String, SherlockSite)] = []
        for hit in hits {
            guard let site = sites[hit.source] else { continue }
            if await SherlockReliability.shared.verdict(for: hit.source) == nil, site.accepts(control) {
                unchecked.append((hit.source, site))
            }
        }
        let budget = Date().addingTimeInterval(20)
        await withTaskGroup(of: (String, Bool)?.self) { group in
            var iterator = unchecked.makeIterator()
            var running = 0
            while running < 20, let (name, site) = iterator.next() {
                group.addTask { await (name, checkSite(name, site, username: control, app: app, userAgent: userAgent) == nil) }
                running += 1
            }
            for await outcome in group {
                if let (name, reliable) = outcome { await SherlockReliability.shared.record(name, reliable: reliable) }
                if Date() < budget, let (name, site) = iterator.next() {
                    group.addTask { await (name, checkSite(name, site, username: control, app: app, userAgent: userAgent) == nil) }
                }
            }
        }
        var kept: [PluginResult] = []
        for hit in hits where await SherlockReliability.shared.verdict(for: hit.source) != false {
            kept.append(hit)
        }
        if kept.count < hits.count {
            pluginLogger.info("BulkUsername: dropped \(hits.count - kept.count) hit(s) from sites that also 'found' a name nobody has.")
        }
        return kept
    }

    /// Checks a single Sherlock site for the username. Returns a hit or nil.
    /// Static so the sliding-window task group can call it without capturing
    /// `self`; the pure detection logic lives in `evaluate` so it's unit-testable.
    private static func checkSite(
        _ siteName: String,
        _ siteData: SherlockSite,
        username: String,
        app: Application,
        userAgent: String
    ) async -> PluginResult? {
        let targetURL = siteData.url.replacingOccurrences(of: "{}", with: username)
        let probe = siteData.request(for: username)
        guard let url = URL(string: probe.url) else { return nil }
        // Only the message method needs the body; the rest decide on status +
        // final URL, so skip downloading bodies we won't read.
        let needsBody = siteData.errorType == "message"
        let headers = [
            "User-Agent": userAgent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        ].merging(probe.headers) { _, site in site }
        do {
            let response = try await OutboundHTTP.request(
                url,
                method: probe.method,
                headers: headers,
                body: probe.body,
                timeout: 10,
                bodyMode: needsBody ? .complete(maxBytes: 512 * 1_024) : .prefix(maxBytes: 0),
                maxRedirects: 3,
                on: app
            )
            return evaluate(siteName: siteName, siteData: siteData, username: username,
                            targetURL: targetURL, status: response.status,
                            finalURL: response.finalURL, body: response.data)
        } catch {
            return nil
        }
    }

    /// Pure detection: turn a fetched response into a hit (or nil). Split out so
    /// the anti-false-positive rules can be unit-tested without the network.
    ///
    /// The key rule: a real profile keeps the username in its final URL. Sites
    /// whose "user not found" page 3xx-redirects to a home/login page drop the
    /// username, so requiring it in the final host+path (query excluded, to avoid
    /// `?next=/u/<name>` echoes) rejects that whole class of false positives —
    /// while still accepting subdomain profiles (`user.tumblr.com`) and apex
    /// redirects (`www.github.com/user` → `github.com/user`).
    static func evaluate(
        siteName: String,
        siteData: SherlockSite,
        username: String,
        targetURL: String,
        status: Int,
        finalURL: URL,
        body: Data
    ) -> PluginResult? {
        func hit(_ confidence: Double, _ how: String) -> PluginResult {
            PluginResult(source: siteName, type: "account_presence", confidenceScore: confidence,
                         rawData: "Account found (\(how)). Profile: \(targetURL)",
                         metadata: ["platform": siteName, "username": username, "profileURL": targetURL])
        }

        // Username preserved in the destination's host or path (not the query),
        // or no redirect at all: a probe may carry the name in its query or
        // body, and an answer from the very URL asked is about that name.
        let locus = ((finalURL.host ?? "") + finalURL.path).lowercased()
        let asked = siteData.request(for: username).url
        let trim = CharacterSet(charactersIn: "/")
        let unredirected = finalURL.absoluteString.trimmingCharacters(in: trim) == asked.trimmingCharacters(in: trim)
        let mentionsUser = locus.contains(username.lowercased()) || unredirected

        switch siteData.errorType {
        case "response_url":
            guard let errorURL = siteData.errorUrl, !errorURL.isEmpty else { return nil }
            let errTrim = errorURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let finalTrim = finalURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            if finalTrim.hasPrefix(errTrim) { return nil } // bounced to the known "not found" URL
            return hit(0.8, "redirect-based")

        case "status_code":
            guard (200..<300).contains(status), !(siteData.errorCode?.codes.contains(status) ?? false),
                  mentionsUser else { return nil }
            return hit(0.7, "HTTP 200")

        case "message":
            guard status == 200, mentionsUser else { return nil }
            let html = String(decoding: body, as: UTF8.self)
            if let errorMsg = siteData.errorMsg {
                switch errorMsg {
                case .string(let s): if html.contains(s) { return nil }
                case .array(let a): if a.contains(where: { html.contains($0) }) { return nil }
                }
            }
            return hit(0.85, "message-based")

        default:
            return nil
        }
    }
}
