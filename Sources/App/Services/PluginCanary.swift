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
    }

    static let checks: [Check] = [
        Check(plugin: "GitHubAccountCheck", input: "torvalds", username: "torvalds"),
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
        Check(plugin: "CratesPackages", input: "dtolnay", username: "dtolnay"),
        Check(plugin: "CertificateTransparency", input: "example.com", username: nil, alerts: false),
        Check(plugin: "DomainOSINT", input: "example.com", username: nil),
        Check(plugin: "InternetDB", input: "8.8.8.8", username: nil),
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
            guard let plugin = plugins.first(where: { $0.name == check.plugin }) else { continue }
            var report = await run(check, plugin: plugin, app: app, timeout: timeout)
            for delay in retryDelays where !report.passed {
                try? await Task.sleep(for: .seconds(delay))
                report = await run(check, plugin: plugin, app: app, timeout: timeout)
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

    static func run(_ check: Check, plugin: any FootprintPlugin, app: Application, timeout: Double) async -> Report {
        let started = Date()
        let outcome: Swift.Result<[PluginResult], Error>? = await withTaskGroup(of: Swift.Result<[PluginResult], Error>?.self) { group in
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
