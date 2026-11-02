import Vapor
import Foundation

/// Daily check that each source still finds an account known to exist.
///
/// `PluginHealth` sees a source that refuses or drops requests, but not one
/// that still answers 200 in a changed format: the plugin's parser finds
/// nothing, returns "no account", and the run counts as healthy. It also only
/// learns from real scans, so a quiet day hides a broken source. A canary
/// closes both gaps: every plugin is run on a public account that exists, and
/// one that no longer finds it is broken, whatever its HTTP calls said.
///
/// Targets are long-lived public accounts of the platforms' own founders,
/// projects or staff, or reserved documentation names (`example.com`).
/// Plugins that need an API key, and the heavy sweeps, have no canary: a
/// missing key is configuration, not breakage, and a sweep costs hundreds of
/// requests.
///
/// Results reach the operator through `/ready` (`pluginCanaryFailing`), which
/// the host healthcheck reads every fifteen minutes and alerts on; the admin
/// page shows each plugin's last canary.
enum PluginCanary {
    struct Check: Sendable {
        let plugin: String
        let input: String
        /// When set, a result must carry this `username` (any case); otherwise
        /// any result passes.
        let username: String?
        /// False for a source whose own outages are routine (crt.sh serves
        /// 502s for minutes at a time): its failures show on the admin page
        /// but do not page anyone, because there is nothing to fix here.
        var alerts = true
        /// For a source with a small quota shared with real scans (GreyNoise's
        /// keyless API: 25 lookups a week per address). Its answer is kept in
        /// the plugin cache, so it survives the restarts that rerun every
        /// canary on each deploy, and reused for this long after a pass (a
        /// day after a miss). A miss is not retried. Asked on every boot with
        /// retries, the check alone used most of the week's lookups.
        var reuseFor: TimeInterval?
    }

    static let checks: [Check] = [
        Check(plugin: "GitHubAccountCheck", input: "torvalds", username: "torvalds"),
        Check(plugin: "GitHubCommitEmail", input: "dtolnay@gmail.com", username: "dtolnay"),
        Check(plugin: "OpenPGPKeys", input: "dkg@fifthhorseman.net", username: nil),
        Check(plugin: "PGPKeyserver", input: "dkg@fifthhorseman.net", username: nil),
        // Keybase's co-founder proves twitter:malgorithms from user "chris".
        Check(plugin: "KeybaseProofs", input: "malgorithms", username: "chris"),
        Check(plugin: "GitLabAccountCheck", input: "sytses", username: "sytses"),
        Check(plugin: "KeybaseOSINT", input: "chris", username: "chris"),
        Check(plugin: "TelegramOSINT", input: "durov", username: "durov"),
        Check(plugin: "MastodonOSINT", input: "Gargron", username: "Gargron"),
        Check(plugin: "HackerNews", input: "pg", username: "pg"),
        Check(plugin: "NpmPackages", input: "sindresorhus", username: "sindresorhus"),
        Check(plugin: "PyPIPackages", input: "dstufft", username: nil),
        Check(plugin: "SteamAccountCheck", input: "gabelogannewell", username: nil),
        Check(plugin: "BlueskyOSINT", input: "jay.bsky.team", username: "jay.bsky.team"),
        Check(plugin: "DockerHub", input: "jessfraz", username: "jessfraz"),
        Check(plugin: "Codeberg", input: "fnetX", username: "fnetX"),
        Check(plugin: "SSHKeys", input: "fnetX", username: "fnetX"),
        Check(plugin: "DevTo", input: "ben", username: "ben"),
        // A sample address that sits in hundreds of breach lists.
        Check(plugin: "XposedOrNot", input: "test@example.com", username: nil),
        Check(plugin: "LeakCheck", input: "test@example.com", username: nil),
        Check(plugin: "MicrosoftTenant", input: "microsoft.com", username: nil),
        Check(plugin: "Lobsters", input: "pushcx", username: "pushcx"),
        // Duolingo's co-founder holds user id 14.
        Check(plugin: "Duolingo", input: "luis", username: "luis"),
        Check(plugin: "Lichess", input: "thibault", username: "thibault"),
        Check(plugin: "Speedrun", input: "cheese", username: "cheese"),
        Check(plugin: "Linktree", input: "selenagomez", username: "selenagomez"),
        Check(plugin: "HuggingFace", input: "julien-c", username: "julien-c"),
        Check(plugin: "GravatarProfile", input: "beau", username: "beau"),
        Check(plugin: "Codeforces", input: "tourist", username: "tourist"),
        Check(plugin: "LeetCode", input: "neal_wu", username: "neal_wu"),
        Check(plugin: "Wattpad", input: "Wattpad", username: "Wattpad"),
        // TikTok serves its page to some visitors as a challenge instead.
        Check(plugin: "TikTok", input: "tiktok", username: "tiktok", alerts: false),
        Check(plugin: "YouTube", input: "mkbhd", username: "mkbhd"),
        Check(plugin: "Substack", input: "platformer", username: "platformer"),
        Check(plugin: "Mixcloud", input: "spartacus", username: "spartacus"),
        // Wikipedia's co-founder; the account is named with a space.
        Check(plugin: "Wikimedia", input: "Jimbo_Wales", username: "Jimbo Wales"),
        // A Tor exit relay run by a German non-profit since 2019. Without a
        // key proxycheck.io answers 100 lookups a day: scans can spend them.
        Check(plugin: "ProxyCheck", input: "185.220.101.1", username: nil, alerts: false),
        Check(plugin: "CratesPackages", input: "dtolnay", username: "dtolnay"),
        Check(plugin: "CertificateTransparency", input: "example.com", username: nil, alerts: false),
        Check(plugin: "DomainOSINT", input: "example.com", username: nil),
        Check(plugin: "InternetDB", input: "8.8.8.8", username: nil),
        Check(plugin: "RIPEstat", input: "8.8.8.8", username: nil),
        // Keyed sources: a canary also catches a key that expired or was
        // revoked. One request a day each; skipped while not configured.
        Check(plugin: "Shodan", input: "8.8.8.8", username: nil),
        Check(plugin: "VirusTotal", input: "8.8.8.8", username: nil),
        Check(plugin: "AbuseIPDB", input: "8.8.8.8", username: nil),
        Check(plugin: "PhoneOSINT", input: "+14152007986", username: nil),
        // One of Shodan's census scanners, which GreyNoise classifies while it
        // keeps scanning. Scanner addresses do retire: 71.6.135.131 dropped
        // out of GreyNoise's window on 2026-11-01 and failed this check daily.
        // Shown, never alerted on: the keyless API allows a few dozen lookups
        // a week per address, so a daily check with retries can exhaust it.
        Check(plugin: "GreyNoise", input: "71.6.199.23", username: nil, alerts: false, reuseFor: 7 * 86_400),
        Check(plugin: "MailSecurity", input: "google.com", username: nil),
        Check(plugin: "SiteMeta", input: "github.com", username: nil),
        Check(plugin: "Wayback", input: "rfc-editor.org", username: nil),
        Check(plugin: "WebPosture", input: "example.com", username: nil),
        Check(plugin: "WHOIS", input: "example.com", username: nil),
    ]

    /// Whether `results` found what `check` expects.
    static func passes(_ results: [PluginResult], check: Check) -> Bool {
        guard let expected = check.username?.lowercased() else { return !results.isEmpty }
        return results.contains { $0.metadata?["username"]?.lowercased() == expected }
    }

    struct Report: Sendable, Codable, Equatable {
        let plugin: String
        let input: String
        let passed: Bool
        var alerts = true
        let results: Int
        let detail: String?
        let checkedAt: Date
    }

    /// Runs every check, one plugin at a time so a canary never bursts at a
    /// source, and stores the reports. A failed check is tried again after
    /// each of `retryDelays` and counts as failed only if every attempt does:
    /// crt.sh answers the same query with a 502 in two seconds, a 200 in
    /// twenty-six or a 200 in a tenth of one, in bursts that outlast a short
    /// pause. A broken source fails all three; a flaky one passes one.
    static func runAll(plugins: [any FootprintPlugin], app: Application, checks: [Check] = checks,
                       timeout: Double = 90, retryDelays: [Double] = [60, 300]) async {
        var failing: [String] = []
        var paging = false
        for check in checks {
            // An unconfigured plugin never runs in a scan either; its missing
            // key is shown on the admin page, not paged on.
            guard let plugin = plugins.first(where: { $0.name == check.plugin }), plugin.isConfigured else { continue }
            var report: Report
            if let reuse = check.reuseFor {
                report = await runSparingly(check, plugin: plugin, app: app, timeout: timeout, reuseFor: reuse)
            } else {
                report = await run(check, plugin: plugin, app: app, timeout: timeout)
                for delay in retryDelays where !report.passed {
                    try? await Task.sleep(for: .seconds(delay))
                    report = await run(check, plugin: plugin, app: app, timeout: timeout)
                }
            }
            report.alerts = check.alerts
            await PluginCanaryStore.shared.record(report)
            if !report.passed {
                failing.append("\(check.plugin) (\(report.detail ?? "no result"))")
                paging = paging || check.alerts
            }
        }
        if failing.isEmpty {
            app.logger.notice("[PluginCanary] all \(checks.count) canaries found their account.")
        } else if paging {
            app.logger.error("[PluginCanary] \(failing.count) canary check(s) failed: \(failing.joined(separator: ", ")).")
        } else {
            // Only sources whose outages are routine: worth a line, not an error.
            app.logger.warning("[PluginCanary] \(failing.count) non-paging canary check(s) failed: \(failing.joined(separator: ", ")).")
        }
    }

    /// A quota-limited check: a recent answer from the plugin cache when there
    /// is one, otherwise one live attempt whose answer is kept for next time.
    static func runSparingly(_ check: Check, plugin: any FootprintPlugin, app: Application,
                             timeout: Double, reuseFor: TimeInterval) async -> Report {
        let key = "canary:" + check.plugin
        if let kept = await PluginCacheStore.lookup(pluginName: key, input: check.input, on: app.db, logger: app.logger) {
            return report(check, outcome: .success(kept), started: Date(), timeout: timeout)
        }
        let started = Date()
        let outcome = await attempt(check, plugin: plugin, app: app, timeout: timeout)
        let report = report(check, outcome: outcome, started: started, timeout: timeout)
        // Timeouts and errors are not kept: they rarely spend a lookup.
        if case .success(let results)? = outcome {
            await PluginCacheStore.store(pluginName: key, input: check.input, results: results,
                                         ttl: report.passed ? reuseFor : min(reuseFor, 86_400),
                                         on: app.db, logger: app.logger)
        }
        return report
    }

    static func run(_ check: Check, plugin: any FootprintPlugin, app: Application, timeout: Double) async -> Report {
        let started = Date()
        return report(check, outcome: await attempt(check, plugin: plugin, app: app, timeout: timeout),
                      started: started, timeout: timeout)
    }

    /// One scan of the check's input, or nil when it outlasted `timeout`.
    static func attempt(_ check: Check, plugin: any FootprintPlugin, app: Application,
                        timeout: Double) async -> Swift.Result<[PluginResult], Error>? {
        await withTaskGroup(of: Swift.Result<[PluginResult], Error>?.self) { group in
            group.addTask {
                do { return .success(try await plugin.scan(input: check.input, on: app)) } catch { return .failure(error) }
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(timeout))
                return nil
            }
            let first = await group.next().flatMap { $0 }
            group.cancelAll()
            return first
        }
    }

    static func report(_ check: Check, outcome: Swift.Result<[PluginResult], Error>?,
                       started: Date, timeout: Double) -> Report {
        switch outcome {
        case .none:
            return Report(plugin: check.plugin, input: check.input, passed: false, results: 0,
                          detail: "timed out after \(Int(timeout))s", checkedAt: started)
        case .failure(let error)?:
            return Report(plugin: check.plugin, input: check.input, passed: false, results: 0,
                          detail: "error: \(String(describing: error).prefix(120))", checkedAt: started)
        case .success(let results)?:
            let passed = passes(results, check: check)
            return Report(plugin: check.plugin, input: check.input, passed: passed, results: results.count,
                          detail: passed ? nil : (results.isEmpty ? "no result" : "account not in results"),
                          checkedAt: started)
        }
    }
}

/// Last canary report per plugin, process-local like `PluginHealth`.
actor PluginCanaryStore {
    static let shared = PluginCanaryStore()
    private var reports: [String: PluginCanary.Report] = [:]

    func record(_ report: PluginCanary.Report) { reports[report.plugin] = report }
    func report(for plugin: String) -> PluginCanary.Report? { reports[plugin] }
    /// Failed canaries that should page: the list `/ready` publishes.
    func failing() -> [String] { reports.values.filter { !$0.passed && $0.alerts }.map(\.plugin).sorted() }
    func lastRun() -> Date? { reports.values.map(\.checkedAt).max() }

    /// Test seam.
    func reset() { reports.removeAll() }
}

/// Runs the canaries ten minutes after boot (so a deploy is checked against
/// real sources too) and then once a day.
struct PluginCanaryRunner: LifecycleHandler {
    static let firstDelay: Double = 600
    static let interval: Double = 86_400

    func didBoot(_ application: Application) throws {
        guard application.environment != .testing else { return }
        let app = application
        Task {
            try? await Task.sleep(for: .seconds(Self.firstDelay))
            while !Task.isCancelled {
                await PluginCanary.runAll(plugins: ScanController.defaultPlugins, app: app)
                try? await Task.sleep(for: .seconds(Self.interval))
            }
        }
    }
}
