import Vapor
import Fluent
import Foundation

/// Cross-plugin result cache. Each (plugin, target) pair is stored once and
/// reused until its TTL elapses. Cuts external-API calls dramatically on
/// repeated scans of the same target.
///
/// Design:
///   • Cache key = (plugin_name, HMAC-SHA256(lowercased + trimmed input)).
///   • TTL is supplied by the caller from the plugin's own `cacheTTL` property
///     (see `FootprintPlugin`). It used to live in a central name→TTL map here,
///     which silently fell back to the default whenever a plugin's `name` didn't
///     match a key — and most keys had drifted out of sync, so tuned TTLs (e.g.
///     HIBP's 24h) were never applied. Per-plugin declaration removes that class
///     of bug entirely.
///   • Best-effort: any DB error during lookup/store is swallowed — a cache
///     miss just makes the plugin re-run. Never block a scan on cache I/O.
///   • Scheduled scans bypass the cache (see ScanPluginRunner.run) because
///     monitor mode is specifically about detecting *new* findings.
///   • Set PLUGIN_CACHE_DISABLED=true to opt-out entirely (debugging).
enum PluginCacheStore {

    static var isEnabled: Bool {
        (Environment.get("PLUGIN_CACHE_DISABLED")?.lowercased() != "true")
    }

    /// Normalize before hashing so "user@x.com" and "  USER@X.com " share a cache row.
    private static func hash(_ input: String) -> String {
        let normalized = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return FieldCrypto.blindIndex(normalized)
    }

    /// Returns cached results if the entry exists and hasn't expired, else nil.
    static func lookup(pluginName: String, input: String, on db: Database) async -> [PluginResult]? {
        guard isEnabled else { return nil }
        let h = hash(input)
        let result: [PluginResult]? = await {
            do {
                guard let entry = try await PluginCacheEntry.query(on: db)
                    .filter(\.$pluginName == pluginName)
                    .filter(\.$targetHash == h)
                    .first()
                else { return nil }
                guard entry.expiresAt > Date() else { return nil }
                let payload: String
                if let decrypted = TokenEncryption.decrypt(entry.payload) {
                    payload = decrypted
                } else if TokenEncryption.isEncryptedEnvelope(entry.payload) {
                    return nil
                } else {
                    payload = entry.payload // legacy plaintext cache row
                }
                guard let data = payload.data(using: .utf8),
                      let decoded = try? JSONDecoder().decode([PluginResult].self, from: data)
                else { return nil }
                return decoded
            } catch {
                return nil
            }
        }()
        // Bump hit/miss counters so `/metrics` can surface cache effectiveness.
        // Disabled paths (PLUGIN_CACHE_DISABLED=true) are excluded above, so
        // this only counts real lookup attempts.
        if result != nil {
            await MetricsRegistry.shared.incPluginCacheHit()
        } else {
            await MetricsRegistry.shared.incPluginCacheMiss()
        }
        return result
    }

    /// Persists plugin output for `ttl` seconds (the plugin's own `cacheTTL`).
    /// Failures are swallowed — the cache is non-critical; a write error just
    /// means a future re-run.
    static func store(pluginName: String, input: String, results: [PluginResult], ttl: TimeInterval, on db: Database, logger: Logger) async {
        guard isEnabled else { return }
        let h = hash(input)
        guard let body = try? JSONEncoder().encode(results),
              let plaintext = String(data: body, encoding: .utf8)
        else { return }
        let payload = FieldCrypto.encrypt(plaintext)
        let expires = Date().addingTimeInterval(ttl)

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
