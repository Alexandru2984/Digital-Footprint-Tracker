import Foundation

/// Renders a synthesized identity as a GraphML document — the open graph-interchange
/// XML that Gephi, yEd and Cytoscape read directly and that imports into Maltego. This
/// turns a flat scan into a navigable relationship graph for real pivot analysis.
///
/// Topology is a typed star around the target: every discovered entity — names, emails,
/// phones, aliases, confirmed accounts, breaches, exposed IPs, locations and orgs —
/// becomes a typed node linked back to the target by a typed edge. Aliases additionally
/// link to any account whose reference mentions that handle, so the alias → where-it's-used
/// structure survives the export instead of collapsing into a plain star.
///
/// Pure and dependency-free, so it unit-tests without a database or HTTP.
enum IdentityGraph {

    static func graphml(from profile: IdentitySynthesizer.IdentityProfile, target: String) -> String {
        var nodes: [String] = []
        var edges: [String] = []
        var counter = 0
        func nextID() -> String { defer { counter += 1 }; return "n\(counter)" }

        func node(_ id: String, _ label: String, _ type: String, _ confidence: Double? = nil) {
            var s = "    <node id=\"\(id)\">\n"
            s += "      <data key=\"label\">\(esc(label))</data>\n"
            s += "      <data key=\"type\">\(esc(type))</data>\n"
            if let c = confidence {
                s += "      <data key=\"confidence\">\(String(format: "%.2f", c))</data>\n"
            }
            s += "    </node>"
            nodes.append(s)
        }
        func edge(_ src: String, _ dst: String, _ rel: String) {
            edges.append("    <edge source=\"\(src)\" target=\"\(dst)\">\n      <data key=\"rel\">\(esc(rel))</data>\n    </edge>")
        }

        // Root: the scan target.
        let root = nextID()
        node(root, target, "target")

        // Simple star categories: a node per value, edge target -> value.
        func star(_ values: [String], type: String, rel: String) {
            for v in values {
                let id = nextID()
                node(id, v, type)
                edge(root, id, rel)
            }
        }
        for name in profile.names {
            let id = nextID()
            node(id, name, "person")
            edge(root, id, name == profile.likelyName ? "likely-name" : "name")
        }
        star(profile.emails, type: "email", rel: "email")
        star(profile.phones, type: "phone", rel: "phone")
        star(profile.breaches, type: "breach", rel: "breach")
        star(profile.exposedDataClasses, type: "data-class", rel: "exposed-data")
        star(profile.locations, type: "location", rel: "location")
        star(profile.organizations, type: "organization", rel: "affiliation")

        // Exposed IPs, with their open ports and known CVEs hanging off each host —
        // the attack-surface depth (target → IP → {port, CVE}) that makes this graph
        // worth importing instead of a flat list.
        var ipIDs: [String: String] = [:]
        func ipNode(_ ip: String) -> String {
            if let existing = ipIDs[ip] { return existing }
            let id = nextID()
            node(id, ip, "ip")
            edge(root, id, "exposed-ip")
            ipIDs[ip] = id
            return id
        }
        for ip in profile.exposedIPs { _ = ipNode(ip) }
        for svc in profile.exposedServices {
            let host = ipNode(svc.ip)
            for port in svc.ports.prefix(25) {
                let id = nextID()
                node(id, port, "port")
                edge(host, id, "open-port")
            }
            for cve in svc.cves.prefix(25) {
                let id = nextID()
                node(id, cve, "vuln")
                edge(host, id, "vulnerable-to")
            }
        }

        // Aliases carry a confidence and may cross-link to accounts.
        var aliasIDs: [(handle: String, id: String)] = []
        for h in profile.handles {
            let id = nextID()
            node(id, h.handle, "username", h.confidence)
            edge(root, id, "alias")
            aliasIDs.append((h.handle.lowercased(), id))
        }

        // Confirmed accounts; link back to any alias whose handle is named in the reference.
        for acct in profile.confirmedAccounts {
            let id = nextID()
            node(id, "\(acct.platform): \(acct.reference)", "account", acct.confidence)
            edge(root, id, "account")
            let hay = (acct.platform + " " + acct.reference).lowercased()
            for alias in aliasIDs where alias.handle.count >= 3 && hay.contains(alias.handle) {
                edge(alias.id, id, "used-on")
            }
        }

        var out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        out += "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n"
        out += "  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n"
        out += "  <key id=\"type\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n"
        out += "  <key id=\"confidence\" for=\"node\" attr.name=\"confidence\" attr.type=\"double\"/>\n"
        out += "  <key id=\"rel\" for=\"edge\" attr.name=\"relationship\" attr.type=\"string\"/>\n"
        out += "  <graph edgedefault=\"directed\">\n"
        out += "    <desc>Digital footprint of \(esc(target)) — risk \(profile.riskLevel) (\(profile.riskScore))</desc>\n"
        out += nodes.joined(separator: "\n") + "\n"
        if !edges.isEmpty { out += edges.joined(separator: "\n") + "\n" }
        out += "  </graph>\n"
        out += "</graphml>\n"
        return out
    }

    private static func esc(_ s: String) -> String {
        var out = s.replacingOccurrences(of: "&", with: "&amp;")
        out = out.replacingOccurrences(of: "<", with: "&lt;")
        out = out.replacingOccurrences(of: ">", with: "&gt;")
        out = out.replacingOccurrences(of: "\"", with: "&quot;")
        out = out.replacingOccurrences(of: "'", with: "&apos;")
        return out
    }
}
