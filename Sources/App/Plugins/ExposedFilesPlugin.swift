import Vapor
import Foundation

/// Precise detection of sensitive files accidentally served by a web host —
/// exposed `.git` repos, `.env` secrets, database dumps, backup files. These are
/// among the highest-severity real-world leaks (a readable `/.env` hands over
/// live credentials; a readable `/.git` lets an attacker reconstruct source).
///
/// Precision over noise: a 200 status alone is worthless because SPAs (this app
/// included) `try_files … /index.html`, so every path 200s. Each probe therefore
/// requires the body to match a **content signature** unique to that file type,
/// which keeps false positives near zero. `ExposedFiles.classify` is the pure,
/// unit-testable matcher; the plugin only performs the SSRF-guarded fetches.
enum ExposedFiles {
    struct Probe {
        let path: String
        let label: String
        /// Returns true only if `body` genuinely looks like the target file.
        let matches: @Sendable (_ body: String) -> Bool
    }

    static func looksLikeHTML(_ b: String) -> Bool {
        let head = b.prefix(512).lowercased()
        return head.contains("<!doctype html") || head.contains("<html") || head.contains("<head")
    }

    static let probes: [Probe] = [
        Probe(path: "/.env", label: ".env (environment secrets)") { b in
            !looksLikeHTML(b) && b.range(of: #"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*="#, options: .regularExpression) != nil
        },
        Probe(path: "/.git/config", label: ".git/config (exposed Git repo)") { b in
            b.contains("[core]") && b.lowercased().contains("repositoryformatversion")
        },
        Probe(path: "/.git/HEAD", label: ".git/HEAD (exposed Git repo)") { b in
            b.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("ref: refs/")
        },
        Probe(path: "/.svn/wc.db", label: ".svn/wc.db (exposed SVN working copy)") { b in
            b.hasPrefix("SQLite format 3")
        },
        Probe(path: "/.aws/credentials", label: ".aws/credentials (AWS keys)") { b in
            !looksLikeHTML(b) && b.lowercased().contains("aws_access_key_id")
        },
        Probe(path: "/wp-config.php.bak", label: "wp-config.php.bak (WordPress DB creds)") { b in
            b.contains("DB_PASSWORD") || b.contains("DB_NAME")
        },
        Probe(path: "/backup.sql", label: "backup.sql (database dump)") { b in
            let u = b.uppercased(); return u.contains("INSERT INTO ") || u.contains("CREATE TABLE ")
        },
        Probe(path: "/.DS_Store", label: ".DS_Store (directory listing leak)") { b in
            b.contains("Bud1")
        }
    ]

    /// If the file was served (200, or 206 when we asked for a byte range) and
    /// `body` matches the probe at `path`, return the label.
    static func classify(path: String, status: Int, body: String) -> String? {
        guard status == 200 || status == 206,
              let probe = probes.first(where: { $0.path == path }) else { return nil }
        return probe.matches(body) ? probe.label : nil
    }
}

struct ExposedFilesPlugin: FootprintPlugin {
    let name = "ExposedFiles"
    let description = "Content-verified sensitive-file exposure (.env, .git, DB dumps, backups)"
    let cacheTTL: TimeInterval = 14_400 // 4 h
    let heavy = true                    // ~11 fetches per host

    private static let ipv4Pattern = #"^\d{1,3}(\.\d{1,3}){3}$"#

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let domain = CrtShPlugin.normalizeDomain(input)
        guard !domain.contains("@"), domain.contains("."),
              domain.range(of: Self.ipv4Pattern, options: .regularExpression) == nil,
              domain.range(of: #"^[a-z0-9.\-]+$"#, options: .regularExpression) != nil,
              domain.range(of: #"[a-z]"#, options: .regularExpression) != nil else { return [] }

        // SSRF-check the host ONCE (a single blocking getaddrinfo), then probe
        // SEQUENTIALLY with `hostPreChecked`. Sequential is deliberate: firing all
        // probes at once through the shared SafeHTTP singleton raced its lazy
        // URLSession and pinned a blocking resolve per redirect on every worker
        // thread, starving the cooperative pool hard enough to hang the whole
        // process (even /health stopped answering). One at a time is safe, and the
        // per-probe timeout keeps the total bounded well under the runner deadline.
        guard !SSRFGuard.resolvesToInternal(domain) else { return [] }

        let base = "https://\(domain)"
        var out: [PluginResult] = []
        // Hard wall-clock cap so this plugin can never be the long pole of a scan,
        // no matter how a target stalls each fetch.
        let deadline = Date().addingTimeInterval(24)
        for probe in ExposedFiles.probes {
            if Date() > deadline || Task.isCancelled { break }
            guard let url = URL(string: base + probe.path),
                  let resp = try? await SafeHTTP.shared.get(url: url, timeout: 6, wantBody: true, hostPreChecked: true),
                  let body = resp.bodyPrefix,
                  let label = ExposedFiles.classify(path: probe.path, status: resp.status, body: body)
            else { continue }
            out.append(PluginResult(
                source: "ExposedFiles", type: "exposed_file", confidenceScore: 0.95,
                rawData: "Exposed \(label) at \(base)\(probe.path)",
                metadata: ["domain": domain, "path": probe.path, "url": base + probe.path]))
        }
        return out
    }
}
