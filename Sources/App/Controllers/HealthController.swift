import Vapor
import Fluent
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct HealthController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        // /health runs a DB liveness query — rate-limit so a request flood
        // can't saturate the Postgres connection pool. A 60/min ceiling is
        // far above any legitimate monitor (Prometheus 30 s = 2/min,
        // aggressive uptime checks at 5 s = 12/min).
        routes.grouped(ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60))
            .get("health", use: health)
        routes.get("metrics", use: metrics)
        // Registered at /geolocate (not /api/geolocate) — nginx strips the /api/
        // prefix when forwarding, so the public URL remains /api/geolocate.
        // Rate-limited even though it's now fully offline (bounded CPU per call).
        routes.grouped(ScanRateLimiter(anonMax: 5, authedMax: 30, windowSeconds: 60))
            .post("geolocate", use: geolocate)
    }

    struct GeoQuery: Content { let query: String }

    /// Resolve a batch of IPs against the **local** GeoLite2 database.
    ///
    /// Privacy-first: this used to proxy the caller's list of IPs to
    /// `http://ip-api.com` over cleartext HTTP — a third party (and any on-path
    /// observer) learned exactly which hosts were being investigated. It now
    /// answers from a memory-mapped file on disk; nothing leaves the box.
    ///
    ///   • Authentication required — geolocation is an account feature.
    ///   • 4 KB body cap; JSON-array structural check; ≤ 100 entries.
    ///   • Accepts `["1.2.3.4", …]` or `[{"query":"1.2.3.4"}, …]`.
    ///   • Response shape matches the previous ip-api batch (status/query/lat/
    ///     lon/city/regionName/country/countryCode) so the map UI is unchanged.
    @Sendable func geolocate(req: Request) async throws -> [GeoIP.Location] {
        guard try await req.currentUser() != nil else {
            throw Abort(.unauthorized, reason: "Authentication required.")
        }
        guard let bodyData = req.body.data else {
            throw Abort(.badRequest, reason: "Request body required.")
        }
        guard bodyData.readableBytes <= 4096 else {
            throw Abort(.payloadTooLarge, reason: "Body must be ≤ 4 KB.")
        }
        let bodyBytes = Data(bodyData.readableBytesView)
        guard let top = try? JSONSerialization.jsonObject(with: bodyBytes), let arr = top as? [Any] else {
            throw Abort(.badRequest, reason: "Body must be a JSON array.")
        }
        // Normalise both accepted shapes to a flat list of IP strings.
        let queries: [String] = arr.prefix(100).compactMap { item in
            if let s = item as? String { return s }
            if let d = item as? [String: Any], let q = d["query"] as? String { return q }
            return nil
        }

        guard let geo = req.application.geoIP else {
            // No DB loaded — return all-fail rather than 500 so the UI degrades
            // to "no map data" instead of erroring.
            return queries.map { GeoIP.Location(query: $0, status: "fail") }
        }
        return queries.map { geo.lookup($0) }
    }

    @Sendable func health(req: Request) async throws -> Response {
        let dbOk: Bool
        do {
            _ = try await User.query(on: req.db).count()
            dbOk = true
        } catch {
            dbOk = false
        }

        let payload: [String: Any] = [
            "status": dbOk ? "ok" : "degraded",
            "db": dbOk ? "ok" : "error",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted)
        return Response(
            status: dbOk ? .ok : .serviceUnavailable,
            headers: HTTPHeaders([("Content-Type", "application/json")]),
            body: .init(data: data)
        )
    }

    /// Prometheus-format metrics scrape endpoint.
    ///
    /// Auth modes (checked in order):
    ///   1. METRICS_TOKEN env var set + matching `Authorization: Bearer <token>`
    ///      → allowed. Constant-time compare. Intended for Prometheus scrapers.
    ///   2. Caller is an authenticated admin session → allowed (legacy / manual).
    ///   3. Otherwise 401 (no METRICS_TOKEN set + not admin) or 403.
    ///
    /// Output format: Prometheus text 0.0.4 with HELP + TYPE comments. Counters
    /// are suffixed `_total` per the Prometheus naming convention; gauges
    /// (scan-status snapshot from the DB) are unsuffixed.
    @Sendable func metrics(req: Request) async throws -> Response {
        // ─── Auth ──────────────────────────────────────────────────────────
        if let expected = Environment.get("METRICS_TOKEN")?.trimmingCharacters(in: .whitespaces),
           !expected.isEmpty {
            let provided = req.headers.bearerAuthorization?.token ?? ""
            guard MetricsAuth.constantTimeEqual(provided, expected) else {
                throw Abort(.unauthorized, reason: "Invalid or missing bearer token.")
            }
        } else {
            // Token auth not configured → fall back to admin session.
            guard let user = try await req.currentUser(), user.isAdmin else {
                throw Abort(.forbidden, reason: "Admin or METRICS_TOKEN required.")
            }
        }

        // ─── Gather ────────────────────────────────────────────────────────
        let totalScans     = (try? await Scan.query(on: req.db).count()) ?? 0
        let totalUsers     = (try? await User.query(on: req.db).count()) ?? 0
        let totalResults   = (try? await App.Result.query(on: req.db).count()) ?? 0
        let completedScans = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "completed").count()) ?? 0
        let failedScans    = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "failed").count()) ?? 0
        let pendingScans   = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "pending").count()) ?? 0
        let runningScans   = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "running").count()) ?? 0
        let activeScheduled = (try? await ScheduledScan.query(on: req.db).filter(\.$isActive == true).count()) ?? 0
        let pluginCacheRows = (try? await PluginCacheEntry.query(on: req.db).count()) ?? 0

        let yesterday    = Date().addingTimeInterval(-86400)
        let scansLast24h = (try? await Scan.query(on: req.db).filter(\.$createdAt >= yesterday).count()) ?? 0

        let snap = await MetricsRegistry.shared.snapshot()

        // ─── Format (Prometheus text 0.0.4) ────────────────────────────────
        var out = ""

        func writeCounter(name: String, help: String, value: UInt64) {
            out += "# HELP \(name) \(help)\n"
            out += "# TYPE \(name) counter\n"
            out += "\(name) \(value)\n"
        }
        func writeGauge(name: String, help: String, value: Int) {
            out += "# HELP \(name) \(help)\n"
            out += "# TYPE \(name) gauge\n"
            out += "\(name) \(value)\n"
        }

        writeGauge(name: "swift_vapor_scans",
                   help: "Total scans currently in the database.",
                   value: totalScans)
        out += "# HELP swift_vapor_scans_by_status Number of scans by lifecycle status.\n"
        out += "# TYPE swift_vapor_scans_by_status gauge\n"
        out += "swift_vapor_scans_by_status{status=\"completed\"} \(completedScans)\n"
        out += "swift_vapor_scans_by_status{status=\"failed\"} \(failedScans)\n"
        out += "swift_vapor_scans_by_status{status=\"pending\"} \(pendingScans)\n"
        out += "swift_vapor_scans_by_status{status=\"running\"} \(runningScans)\n"

        writeGauge(name: "swift_vapor_scans_last_24h",
                   help: "Number of scans created in the last 24 hours.",
                   value: scansLast24h)
        writeGauge(name: "swift_vapor_users",
                   help: "Total registered users.",
                   value: totalUsers)
        writeGauge(name: "swift_vapor_results",
                   help: "Total scan-result rows across the database.",
                   value: totalResults)
        writeGauge(name: "swift_vapor_scheduled_scans_active",
                   help: "Scheduled scans currently active.",
                   value: activeScheduled)
        writeGauge(name: "swift_vapor_plugin_cache_rows",
                   help: "Live (non-expired plus expired-but-unswept) rows in plugin_cache.",
                   value: pluginCacheRows)

        writeCounter(name: "swift_vapor_plugin_cache_hits_total",
                     help: "Plugin cache lookups that returned a fresh hit since process start.",
                     value: snap.pluginCacheHits)
        writeCounter(name: "swift_vapor_plugin_cache_misses_total",
                     help: "Plugin cache lookups that fell through to a live plugin run since process start.",
                     value: snap.pluginCacheMisses)

        out += "# HELP swift_vapor_notifications_sent_total Notification dispatch attempts by channel since process start.\n"
        out += "# TYPE swift_vapor_notifications_sent_total counter\n"
        // Stable label-order — sort so scrapers don't see noise on output.
        for channel in snap.notificationsSent.keys.sorted() {
            let count = snap.notificationsSent[channel] ?? 0
            out += "swift_vapor_notifications_sent_total{channel=\"\(channel)\"} \(count)\n"
        }

        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "text/plain; version=0.0.4; charset=utf-8")]),
            body: .init(string: out)
        )
    }
}

/// Constant-time string compare for the metrics bearer token. A length-leak
/// is acceptable for a non-secret-length token; what we guard against is the
/// content-comparison early-exit that lets an attacker derive the token byte
/// by byte from response timing.
enum MetricsAuth {
    static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let aBytes = Array(a.utf8)
        let bBytes = Array(b.utf8)
        guard aBytes.count == bBytes.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<aBytes.count {
            diff |= aBytes[i] ^ bBytes[i]
        }
        return diff == 0
    }
}
