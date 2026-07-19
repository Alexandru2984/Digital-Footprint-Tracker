import Foundation

/// Server-side twin of the investigation-board graph model in
/// `frontend/investigation.js`. Used by the watch runner to grow a board exactly
/// the way the client's `mergeScan` does, so a monitored board stays consistent
/// whether a human expanded it or the background check did.
///
/// Pure and dependency-free — unit-testable without a database.
enum BoardGraph {
    struct Node: Codable {
        var id: String
        var label: String?
        var etype: String?
        var root: Bool?
        var expanded: Bool?
        var new: Bool?
        var x: Double?
        var y: Double?
    }
    struct Edge: Codable {
        var source: String
        var target: String
        var rel: String?
    }
    struct Graph: Codable {
        var nodes: [Node]
        var edges: [Edge]
    }

    /// Entity types a scan can be run against (mirrors the client's PIVOTABLE).
    static let pivotable: Set<String> = ["email", "username", "domain", "ip", "phone"]

    static func decode(_ json: String) -> Graph? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(Graph.self, from: d)
    }
    static func encode(_ g: Graph) -> String? {
        guard let d = try? JSONEncoder().encode(g) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    /// A scan result, reduced to the fields entity extraction needs.
    struct ResultInput {
        let source: String
        let type: String
        let rawData: String
        let metadata: [String: String]
    }

    /// Extract typed entity nodes + relationship edges linked to `rootId`. Node
    /// ids are lowercased; freshly-discovered nodes are flagged `new`. This is a
    /// line-for-line port of the client's `mergeScan`.
    static func extract(rootId rawRoot: String, results: [ResultInput]) -> (nodes: [Node], edges: [Edge]) {
        let rootId = rawRoot.lowercased()
        var nodes: [Node] = []
        var edges: [Edge] = []
        var seen = Set<String>()
        var accounts = 0

        func link(_ rawId: String, _ label: String, _ etype: String, _ rel: String) {
            let idl = rawId.lowercased()
            guard !idl.isEmpty, idl != rootId else { return }
            if !seen.contains(idl) {
                seen.insert(idl)
                nodes.append(Node(id: idl, label: String(label.prefix(48)), etype: etype,
                                  root: false, expanded: false, new: true, x: nil, y: nil))
            }
            edges.append(Edge(source: rootId, target: idl, rel: rel))
        }

        for r in results {
            let m = r.metadata
            let t = r.type.lowercased()
            let s = r.source
            if let email = nonEmpty(m["email"]) { link(email, email, "email", "email") }
            if let username = nonEmpty(m["username"]), username.lowercased() != rootId { link(username, username, "username", "alias") }
            if let domain = nonEmpty(m["domain"]), domain.lowercased() != rootId { link(domain, domain, "domain", "domain") }
            if let sub = nonEmpty(m["subdomain"]) { link(sub, sub, "domain", "subdomain") }
            if let ip = nonEmpty(m["ip"]) { link(ip, ip, "ip", "resolves-to") }
            if t.contains("phone"), let v = nonEmpty(m["phone"]) ?? nonEmpty(r.rawData) { link(v, v, "phone", "phone") }
            if t.contains("breach") && t != "breach_check" {
                let name = m["name"] ?? s
                let label = m["name"] ?? (r.rawData.isEmpty ? "breach" : r.rawData)
                link("breach:" + name, String(label.prefix(36)), "breach", "breached-in")
            }
            if t == "exposed_file" {
                link("exposure:" + (m["url"] ?? r.rawData), String((r.rawData.isEmpty ? "exposed file" : r.rawData).prefix(40)), "exposure", "exposes")
            }
            if t == "email_spoofable" {
                link("risk:" + rootId, "email spoofable", "risk", "weak-email")
            }
            if (t.contains("account") || t.contains("social") || t.contains("profile")) && accounts < 40 {
                accounts += 1
                link(rootId + " @ " + s, "@" + s, "account", "account-on")
            }
        }
        return (nodes, edges)
    }

    /// Merge extracted nodes/edges into `graph`, deduping by id / (source,target).
    /// Returns the count of genuinely new nodes added (already flagged `new`).
    @discardableResult
    static func merge(into graph: inout Graph, nodes: [Node], edges: [Edge]) -> Int {
        var haveNodes = Set(graph.nodes.map { $0.id })
        var added = 0
        for n in nodes where !haveNodes.contains(n.id) {
            haveNodes.insert(n.id)
            graph.nodes.append(n)
            added += 1
        }
        var haveEdges = Set(graph.edges.map { $0.source + "\u{1}" + $0.target })
        for e in edges {
            let key = e.source + "\u{1}" + e.target
            if !haveEdges.contains(key) {
                haveEdges.insert(key)
                graph.edges.append(e)
            }
        }
        return added
    }

    private static func nonEmpty(_ s: String?) -> String? {
        guard let s = s, !s.isEmpty else { return nil }
        return s
    }
}
