import Vapor
import Fluent
import Crypto
import Foundation

/// Cross-plugin result cache. Each (plugin, target) pair is stored once and
/// reused until its TTL elapses. Cuts external-API calls dramatically on
/// repeated scans of the same target.
///
/// Design:
///   • Cache key = (plugin_name, sha256(lowercased + trimmed input)).
///   • TTLs are per-plugin (see `ttls` below). Volatile data (threat intel)
///     expires in minutes; stable data (geo, phone carrier) expires in a day.
///   • Best-effort: any DB error during lookup/store is swallowed — a cache
///     miss just makes the plugin re-run. Never block a scan on cache I/O.
///   • Scheduled scans bypass the cache (see ScanPluginRunner.run) because
///     monitor mode is specifically about detecting *new* findings.
///   • Set PLUGIN_CACHE_DISABLED=true to opt-out entirely (debugging).
enum PluginCacheStore {

    // ─── TTL policy ─────────────────────────────────────────────────────────
    // Keys must match the plugin's `.name`. Anything not listed gets defaultTTL.
    private static let ttls: [String: TimeInterval] = [
        // Email + breach data — slow-moving.
        "BulkEmailOSINT":   86_400,   // 24 h
        "HIBP":             86_400,
        "EmailReputation":  86_400,
        // Username presence — accounts can churn but mostly persist.
        "Sherlock":         21_600,   //  6 h
        "BulkUsernameOSINT":21_600,
        // IP threat intel — fastest-changing.
        "Shodan":            3_600,   //  1 h
        "AbuseIPDB":         3_600,
        "VirusTotal":        3_600,
        // Geolocation / phone / WHOIS / DNS / CT-logs — very stable.
        "Geolocate":        86_400,
        "AbstractPhone":    86_400,
        "WHOIS":            14_400,   //  4 h
        "DNS":              14_400,
        "CrtSh":            14_400,
    ]
    private static let defaultTTL: TimeInterval = 3_600

    static var isEnabled: Bool {
        (Environment.get("PLUGIN_CACHE_DISABLED")?.lowercased() != "true")
    }

    static func ttl(for pluginName: String) -> TimeInterval {
        ttls[pluginName] ?? defaultTTL
    }

    /// Normalize before hashing so "user@x.com" and "  USER@X.com " share a cache row.
    private static func hash(_ input: String) -> String {
        let normalized = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = SHA256.hash(data: Data(normalized.utf8))
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    /// Returns cached results if the entry exists and hasn't expired, else nil.
    static func lookup(pluginName: String, input: String, on db: Database) async -> [PluginResult]? {
        guard isEnabled else { return nil }
        let h = hash(input)
        do {
            guard let entry = try await PluginCacheEntry.query(on: db)
                .filter(\.$pluginName == pluginName)
                .filter(\.$targetHash == h)
                .first()
            else { return nil }
            guard entry.expiresAt > Date() else { return nil }
            guard let data = entry.payload.data(using: .utf8),
                  let decoded = try? JSONDecoder().decode([PluginResult].self, from: data)
            else { return nil }
            return decoded
        } catch {
            return nil
        }
    }

    /// Persists plugin output for the plugin's TTL. Failures are swallowed —
    /// the cache is non-critical; a write error just means a future re-run.
    static func store(pluginName: String, input: String, results: [PluginResult], on db: Database, logger: Logger) async {
        guard isEnabled else { return }
        let h = hash(input)
        guard let body = try? JSONEncoder().encode(results),
              let payload = String(data: body, encoding: .utf8)
        else { return }
        let expires = Date().addingTimeInterval(ttl(for: pluginName))

        // Delete-then-insert keeps the upsert dialect-neutral. The unique
        // constraint guards against concurrent inserts of the same key.
        do {
            try await PluginCacheEntry.query(on: db)
                .filter(\.$pluginName == pluginName)
                .filter(\.$targetHash == h)
                .delete()
            let entry = PluginCacheEntry(
                pluginName: pluginName,
                targetHash: h,
                payload: payload,
                expiresAt: expires
            )
            try await entry.save(on: db)
        } catch {
            logger.debug("PluginCache: store failed for \(pluginName): \(error)")
        }
    }
}
