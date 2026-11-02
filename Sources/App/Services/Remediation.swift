import Foundation
import Vapor

/// Turns a scan's security findings into a prioritised list of fixes, each
/// with why it matters, the steps, and where one exists the exact record or
/// configuration to add. The findings say what is wrong; this says what to do,
/// in the order that removes the most risk first.
///
/// Pure: built from the stored results, so the surface tab, the API and the
/// executive report all show the same list.
enum Remediation {
    enum Priority: String, Codable, Sendable, CaseIterable {
        case critical, high, medium, low

        var rank: Int {
            switch self {
            case .critical: return 0
            case .high: return 1
            case .medium: return 2
            case .low: return 3
            }
        }
    }

    struct Fix: Content, Equatable, Sendable {
        /// Stable key (kind and target), so one fix is listed once.
        let id: String
        let priority: Priority
        /// The host, domain or address the fix applies to.
        let target: String
        let title: String
        let why: String
        let steps: [String]
        /// A record or configuration block to copy, when one applies.
        let snippet: String?
    }

    struct Input: Sendable {
        let type: String
        let metadata: [String: String]
        let rawData: String
    }

    /// Ports that should almost never answer on the open internet: remote
    /// desktops, databases, caches, search indexes and legacy protocols.
    static let riskyPorts: [Int: String] = [
        21: "FTP", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 2375: "Docker API",
        3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    ]

    /// Days before a domain's registration lapses when renewing becomes urgent.
    static let domainExpiryWarningDays = 30

    static func fixes(for inputs: [Input], now: Date = Date()) -> [Fix] {
        var fixes: [Fix] = []
        var seen = Set<String>()
        func add(_ fix: Fix) {
            if seen.insert(fix.id).inserted { fixes.append(fix) }
        }

        // Domains whose mail posture was graded, and those with mail servers:
        // missing DNSSEC/CAA can only be stated where the check ran, and a
        // domain that receives no mail gets a "send nothing" SPF.
        let graded = Set(inputs.filter { $0.type.hasPrefix("email_auth_spf") }.compactMap { $0.metadata["domain"] })
        let withMail = Set(inputs.filter { $0.type == "dns_mx_record" }.compactMap { $0.metadata["domain"] })
        let signed = Set(inputs.filter { $0.type == "dnssec_enabled" }.compactMap { $0.metadata["domain"] })
        let withCAA = Set(inputs.filter { $0.type == "dns_caa" }.compactMap { $0.metadata["domain"] })

        for input in inputs {
            let meta = input.metadata
            switch input.type {
            case "exposed_file":
                guard let url = meta["url"] else { continue }
                add(exposedFile(url: url, path: meta["path"] ?? "", domain: meta["domain"] ?? url))
            case "subdomain_takeover":
                guard let host = meta["subdomain"] else { continue }
                add(takeover(host: host, cname: meta["cname"] ?? "", service: meta["service"]))
            case "vulnerability":
                guard let ip = meta["ip"] else { continue }
                add(vulnerable(ip: ip, cves: meta["cves"] ?? "", count: Int(meta["cve_count"] ?? "") ?? 0))
            case "exposed_service":
                guard let ip = meta["ip"], let fix = riskyServices(ip: ip, ports: meta["ports"] ?? "") else { continue }
                add(fix)
            case "email_auth_dmarc_missing":
                guard let domain = meta["domain"] else { continue }
                add(dmarcMissing(domain: domain, receivesMail: withMail.contains(domain)))
            case "email_auth_dmarc":
                guard let domain = meta["domain"], meta["enforced"] == "no" else { continue }
                add(dmarcUnenforced(domain: domain, record: meta["record"]))
            case "email_auth_spf_missing":
                guard let domain = meta["domain"] else { continue }
                add(spfMissing(domain: domain, receivesMail: withMail.contains(domain)))
            case "email_auth_spf":
                guard let domain = meta["domain"], meta["spoofable"] == "yes" else { continue }
                add(spfWeak(domain: domain, record: meta["record"]))
            case "insecure_transport":
                guard let domain = meta["domain"] else { continue }
                add(noHTTPS(domain: domain))
            case "security_headers":
                guard let domain = meta["domain"] else { continue }
                let missing = (meta["missing"] ?? "").split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                if let fix = headers(domain: domain, missing: missing, https: meta["https"] != "no") { add(fix) }
            case "domain_registration":
                guard let domain = meta["domain"], let expiry = meta["expirationDate"],
                      let fix = domainExpiry(domain: domain, expiry: expiry, now: now) else { continue }
                add(fix)
            case "certificate_expiring":
                guard let domain = meta["domain"], let expiry = meta["expires"] else { continue }
                add(certificateExpiring(domain: domain, expiry: expiry, days: Int(meta["days"] ?? "")))
            default:
                continue
            }
        }
        for domain in graded.sorted() {
            if !signed.contains(domain) { add(dnssec(domain: domain)) }
            if !withCAA.contains(domain) { add(caa(domain: domain)) }
        }
        return fixes.sorted {
            ($0.priority.rank, $0.target, $0.id) < ($1.priority.rank, $1.target, $1.id)
        }
    }

    static func fixes(for results: [Result], now: Date = Date()) throws -> [Fix] {
        fixes(for: try results.map {
            Input(type: $0.type, metadata: try $0.metadataObject ?? [:], rawData: try $0.rawData)
        }, now: now)
    }

    // MARK: - Fixes

    static func exposedFile(url: String, path: String, domain: String) -> Fix {
        Fix(
            id: "exposed-file:\(url)", priority: .critical, target: domain,
            title: "Remove the file exposed at \(url)",
            why: "Anyone can download it. Files like this often hold passwords, API keys or the site's source code, "
                + "and automated scanners look for them within hours of a site going up.",
            steps: [
                "Delete \(path.isEmpty ? "the file" : path) from the web root, or move it outside it.",
                "Deny hidden files and backups in the web server configuration (below).",
                "Treat every secret the file held as leaked: rotate passwords, keys and tokens, then check logs for their use.",
            ],
            snippet: """
            # nginx: refuse hidden files (except .well-known) and common dumps
            location ~ /\\.(?!well-known/) { deny all; }
            location ~* \\.(sql|bak|old|swp|tar|tgz|zip|7z)$ { deny all; }
            """
        )
    }

    static func takeover(host: String, cname: String, service: String?) -> Fix {
        let provider = service.flatMap { $0 == "unknown" ? nil : $0 }
        return Fix(
            id: "takeover:\(host)", priority: .critical, target: host,
            title: "Remove the dangling DNS record for \(host)",
            why: "\(host) points at \(cname.isEmpty ? "a resource" : cname), which nobody holds. Whoever claims it"
                + "\(provider.map { " on \($0)" } ?? "") can serve pages, set cookies and receive mail as your domain.",
            steps: [
                "If the subdomain is no longer used, delete its CNAME record.",
                "If it is, claim the resource again\(provider.map { " on \($0)" } ?? "") before someone else does.",
                "Review the other records that point at third-party services the same way.",
            ],
            snippet: cname.isEmpty ? nil : "; delete this record\n\(host). CNAME \(cname)."
        )
    }

    static func vulnerable(ip: String, cves: String, count: Int) -> Fix {
        let listed = cves.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let shown = listed.prefix(5).joined(separator: ", ")
        let total = max(count, listed.count)
        return Fix(
            id: "cve:\(ip)", priority: total >= 10 ? .critical : .high, target: ip,
            title: "Update the software on \(ip) (\(total) known vulnerabilit\(total == 1 ? "y" : "ies"))",
            why: "The versions this server announces have published vulnerabilities"
                + (shown.isEmpty ? "" : " (\(shown)\(total > 5 ? ", …" : ""))")
                + ". Published vulnerabilities are the first thing attackers try.",
            steps: [
                "Find the service behind each port and update it to a supported release.",
                "If a service does not need to be public, bind it to localhost or a private network instead.",
                "Scan again: the list comes from what the server announces, so it clears once versions change.",
            ],
            snippet: nil
        )
    }

    static func riskyServices(ip: String, ports: String) -> Fix? {
        let open = ports.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        let risky = open.filter { riskyPorts[$0] != nil }.sorted()
        guard !risky.isEmpty else { return nil }
        let names = risky.map { "\(riskyPorts[$0] ?? "") (\($0))" }.joined(separator: ", ")
        return Fix(
            id: "ports:\(ip)", priority: .high, target: ip,
            title: "Close \(names) to the internet",
            why: "These services are meant for trusted networks. Exposed, they are brute-forced and exploited "
                + "around the clock, and many ship without a password by default.",
            steps: [
                "Block the ports in the firewall, or bind the services to localhost.",
                "Reach them over a VPN or an SSH tunnel instead.",
                "Check the services' logs for access you do not recognise.",
            ],
            snippet: risky.map { "ufw deny \($0)/tcp" }.joined(separator: "\n")
        )
    }

    static func dmarcMissing(domain: String, receivesMail: Bool) -> Fix {
        Fix(
            id: "dmarc:\(domain)", priority: .high, target: domain,
            title: "Publish a DMARC record for \(domain)",
            why: "Without DMARC, receiving servers have no instruction to reject mail that forges \(domain), "
                + "so it can be used for phishing in your name.",
            steps: receivesMail ? [
                "Add the TXT record below with p=none and a reporting address, to see who sends as the domain.",
                "Once every legitimate sender passes SPF or DKIM (usually two to four weeks), "
                    + "change p=none to p=quarantine, then p=reject.",
            ] : [
                "The domain receives no mail, so it should send none: publish the record below with p=reject.",
            ],
            snippet: receivesMail
                ? "_dmarc.\(domain). TXT \"v=DMARC1; p=none; rua=mailto:dmarc@\(domain)\""
                : "_dmarc.\(domain). TXT \"v=DMARC1; p=reject;\""
        )
    }

    static func dmarcUnenforced(domain: String, record: String?) -> Fix {
        let current = record?.trimmingCharacters(in: .whitespaces) ?? ""
        let enforced = current.isEmpty
            ? "v=DMARC1; p=quarantine;"
            : current.replacingOccurrences(of: #"p\s*=\s*none"#, with: "p=quarantine", options: .regularExpression)
        return Fix(
            id: "dmarc:\(domain)", priority: .medium, target: domain,
            title: "Enforce DMARC for \(domain)",
            why: "The DMARC policy is p=none: forged mail is reported but still delivered.",
            steps: [
                "Check the aggregate reports: every service that sends as \(domain) should pass SPF or DKIM.",
                "Change the policy to p=quarantine, and to p=reject once nothing legitimate is caught.",
            ],
            snippet: "_dmarc.\(domain). TXT \"\(enforced)\""
        )
    }

    static func spfMissing(domain: String, receivesMail: Bool) -> Fix {
        Fix(
            id: "spf:\(domain)", priority: .high, target: domain,
            title: "Publish an SPF record for \(domain)",
            why: "SPF lists the servers allowed to send as \(domain). Without it, any server can claim to.",
            steps: receivesMail ? [
                "List the services that send your mail (your mail provider, newsletter and billing tools).",
                "Publish one TXT record naming them, ending in -all, as below.",
            ] : [
                "The domain receives no mail, so state that it sends none with the record below.",
            ],
            snippet: receivesMail
                ? "\(domain). TXT \"v=spf1 include:<your mail provider> -all\""
                : "\(domain). TXT \"v=spf1 -all\""
        )
    }

    static func spfWeak(domain: String, record: String?) -> Fix {
        let current = record?.trimmingCharacters(in: .whitespaces) ?? ""
        let hardened = current.isEmpty
            ? "v=spf1 include:<your mail provider> -all"
            : current.replacingOccurrences(of: #"[?+~]all\b"#, with: "-all", options: .regularExpression)
        return Fix(
            id: "spf:\(domain)", priority: .medium, target: domain,
            title: "Make the SPF record for \(domain) strict",
            why: "The record does not end in -all, so mail from servers it does not list is still accepted.",
            steps: [
                "Make sure every service that sends as \(domain) is listed.",
                "End the record with -all.",
            ],
            snippet: "\(domain). TXT \"\(hardened)\""
        )
    }

    static func noHTTPS(domain: String) -> Fix {
        Fix(
            id: "https:\(domain)", priority: .high, target: domain,
            title: "Serve \(domain) over HTTPS",
            why: "Over plain HTTP, anyone on the visitor's network can read and change the page, including forms and logins.",
            steps: [
                "Get a free certificate from Let's Encrypt (certbot, or your host's control panel).",
                "Redirect every HTTP request to HTTPS, then add HSTS.",
            ],
            snippet: """
            # nginx
            server {
                listen 80;
                server_name \(domain);
                return 301 https://$host$request_uri;
            }
            """
        )
    }

    static func headers(domain: String, missing: [String], https: Bool) -> Fix? {
        let values: [String: String] = [
            "HSTS": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "CSP": "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always;",
            "X-Frame-Options": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "X-Content-Type-Options": "add_header X-Content-Type-Options \"nosniff\" always;",
            "Referrer-Policy": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "Permissions-Policy": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
        ]
        // HSTS only means something over HTTPS; that fix comes first.
        let wanted = missing.filter { values[$0] != nil && ($0 != "HSTS" || https) }
        guard !wanted.isEmpty else { return nil }
        let major = wanted.contains("HSTS") || wanted.contains("CSP")
        return Fix(
            id: "headers:\(domain)", priority: major ? .medium : .low, target: domain,
            title: "Add the missing security headers on \(domain): \(wanted.joined(separator: ", "))",
            why: "These headers tell browsers to refuse downgrades to HTTP, framing by other sites and injected "
                + "scripts. Without them, a single flaw elsewhere goes further.",
            steps: [
                "Add the headers in the web server or application, as below.",
                "Start the Content-Security-Policy in report-only mode if the site loads scripts from other domains.",
            ],
            snippet: "# nginx (server block)\n" + wanted.compactMap { values[$0] }.joined(separator: "\n")
        )
    }

    static func domainExpiry(domain: String, expiry: String, now: Date) -> Fix? {
        guard let date = day(expiry) else { return nil }
        let days = Int(date.timeIntervalSince(now) / 86_400)
        guard days <= domainExpiryWarningDays else { return nil }
        let lapsed = days < 0
        return Fix(
            id: "domain-expiry:\(domain)", priority: days <= 7 ? .critical : .high, target: domain,
            title: lapsed ? "Renew \(domain): the registration lapsed on \(expiry.prefix(10))"
                          : "Renew \(domain) before \(expiry.prefix(10)) (\(days) day\(days == 1 ? "" : "s") left)",
            why: "When a registration lapses the site and mail stop, and after the grace period anyone can "
                + "register the name and receive what is still sent to it.",
            steps: [
                "Renew at the registrar, and turn on automatic renewal.",
                "Check that the payment method and contact address on the account are current.",
            ],
            snippet: nil
        )
    }

    static func certificateExpiring(domain: String, expiry: String, days: Int?) -> Fix {
        let left = days.map { " (\($0) day\($0 == 1 ? "" : "s") left)" } ?? ""
        return Fix(
            id: "certificate:\(domain)", priority: (days ?? 0) <= 7 ? .critical : .high, target: domain,
            title: "Renew the TLS certificate for \(domain) before \(expiry.prefix(10))\(left)",
            why: "The newest certificate logged for \(domain) is close to expiry and no renewal has been logged. "
                + "Automatic renewal normally replaces it a month ahead, so it has likely stopped working.",
            steps: [
                "Run the renewal by hand (for example `certbot renew --dry-run`, then `certbot renew`) and read the error.",
                "Fix the cause (a DNS change, a blocked port 80, an expired API token) and check the renewal timer runs.",
            ],
            snippet: nil
        )
    }

    static func dnssec(domain: String) -> Fix {
        Fix(
            id: "dnssec:\(domain)", priority: .low, target: domain,
            title: "Sign \(domain) with DNSSEC",
            why: "DNSSEC lets resolvers detect forged DNS answers that would send visitors and mail elsewhere.",
            steps: [
                "Turn on DNSSEC at the DNS host.",
                "Publish the DS record it gives you at the registrar.",
            ],
            snippet: nil
        )
    }

    static func caa(domain: String) -> Fix {
        Fix(
            id: "caa:\(domain)", priority: .low, target: domain,
            title: "Limit who can issue certificates for \(domain) (CAA)",
            why: "A CAA record names the certificate authorities allowed to issue for the domain; others must refuse.",
            steps: ["Publish a CAA record for the authority you use, as below."],
            snippet: "\(domain). CAA 0 issue \"letsencrypt.org\""
        )
    }

    private static func day(_ value: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.date(from: String(value.prefix(10)))
    }
}
