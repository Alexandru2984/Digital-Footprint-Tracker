import Vapor
import Fluent

/// CRUD for saved investigation boards (the persistent, growing relationship
/// graphs built in the graph UI). All endpoints are owner-scoped: a board is only
/// ever visible to the user who created it.
struct InvestigationController: RouteCollection {
    /// Hard cap on a serialized board so a runaway client can't store megabytes.
    static let maxDataBytes = 512 * 1024
    static let maxBoardsPerUser = 25
    static let maxWatchedBoardsPerUser = 5
    static let maxNodes = 500
    static let maxEdges = 1_000

    func boot(routes: RoutesBuilder) throws {
        let inv = routes.grouped("investigations")
        inv.get(use: list)
        inv.post(use: create)
        // Constant path segment — registered before the `:id` group so it is never
        // read as a board id.
        inv.get("index", use: index)
        inv.group(":id") { one in
            one.get(use: get)
            one.put(use: update)
            one.delete(use: remove)
            one.put("watch", use: watch)
        }
    }

    // MARK: - DTOs

    struct Summary: Content {
        let id: String
        let name: String
        let nodeCount: Int
        let updatedAt: Double?
        let watched: Bool
        let newCount: Int
    }
    struct Full: Content {
        let id: String
        let name: String
        let data: String          // graph JSON, plaintext
        let createdAt: Double?
        let updatedAt: Double?
        let watched: Bool
        let watchInterval: String?
        let lastCheckedAt: Double?
    }

    private func summary(_ inv: Investigation) -> Summary {
        let (n, new) = Self.nodeStats(inv.data)
        return Summary(id: inv.id?.uuidString ?? "", name: inv.name,
                       nodeCount: n, updatedAt: inv.updatedAt?.timeIntervalSince1970,
                       watched: inv.watched, newCount: new)
    }
    private func full(_ inv: Investigation) -> Full {
        Full(id: inv.id?.uuidString ?? "", name: inv.name, data: inv.data,
             createdAt: inv.createdAt?.timeIntervalSince1970,
             updatedAt: inv.updatedAt?.timeIntervalSince1970,
             watched: inv.watched, watchInterval: inv.watchInterval,
             lastCheckedAt: inv.lastCheckedAt?.timeIntervalSince1970)
    }

    /// Count nodes (and how many are flagged `new`) without trusting the client.
    private static func nodeStats(_ json: String) -> (count: Int, new: Int) {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nodes = obj["nodes"] as? [[String: Any]] else { return (0, 0) }
        let new = nodes.filter { ($0["new"] as? Bool) == true }.count
        return (nodes.count, new)
    }

    // MARK: - Handlers

    @Sendable
    func list(req: Request) async throws -> [Summary] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let boards = try await Investigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$updatedAt, .descending)
            .all()
        return boards.map(summary)
    }

    struct CreateBody: Content { let name: String; let data: String? }

    @Sendable
    func create(req: Request) async throws -> Full {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let boardCount = try await Investigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .count()
        guard boardCount < Self.maxBoardsPerUser else {
            throw Abort(.tooManyRequests, reason: "Maximum \(Self.maxBoardsPerUser) investigation boards per account.")
        }
        let body = try req.content.decode(CreateBody.self)
        let name = try Self.validName(body.name)
        let data = try Self.validData(body.data ?? #"{"nodes":[],"edges":[]}"#)
        let inv = Investigation(userID: user.id!, name: name, data: data)
        try await inv.save(on: req.db)
        AuditLogger.log(req: req, action: "investigation_create", target: name)
        return full(inv)
    }

    @Sendable
    func get(req: Request) async throws -> Full {
        full(try await owned(req))
    }

    /// Compact index of every board the caller owns: just the node ids per board.
    /// Lets the UI spot entities shared across investigations (and offer to merge
    /// them) in one request instead of fetching every board in full.
    struct IndexEntry: Content { let id: String; let name: String; let nodes: [String] }

    @Sendable
    func index(req: Request) async throws -> [IndexEntry] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let boards = try await Investigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .all()
        return boards.map { inv in
            IndexEntry(id: inv.id?.uuidString ?? "", name: inv.name, nodes: Self.nodeIDs(inv.data))
        }
    }

    private static func nodeIDs(_ json: String) -> [String] {
        guard let d = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let nodes = obj["nodes"] as? [[String: Any]] else { return [] }
        return nodes.compactMap { $0["id"] as? String }
    }

    struct UpdateBody: Content { let name: String?; let data: String? }

    @Sendable
    func update(req: Request) async throws -> Full {
        let inv = try await owned(req)
        let body = try req.content.decode(UpdateBody.self)
        if let name = body.name { inv.name = try Self.validName(name) }
        if let data = body.data { inv.data = try Self.validData(data) }
        try await inv.save(on: req.db)
        return full(inv)
    }

    @Sendable
    func remove(req: Request) async throws -> HTTPStatus {
        let inv = try await owned(req)
        try await inv.delete(on: req.db)
        return .noContent
    }

    struct WatchBody: Content { let watched: Bool; let interval: String? }

    /// Turn live monitoring on/off for a board. When enabled, the first check is
    /// scheduled shortly after so the user sees it work.
    @Sendable
    func watch(req: Request) async throws -> Full {
        let inv = try await owned(req)
        let body = try req.content.decode(WatchBody.self)
        if body.watched {
            guard let user = try await req.currentUser(), user.emailVerified else {
                throw Abort(.forbidden, reason: "Verify your email before enabling board monitoring.")
            }
            if !inv.watched {
                let watchedCount = try await Investigation.query(on: req.db)
                    .filter(\.$user.$id == user.id!)
                    .filter(\.$watched == true)
                    .count()
                guard watchedCount < Self.maxWatchedBoardsPerUser else {
                    throw Abort(.tooManyRequests, reason: "Maximum \(Self.maxWatchedBoardsPerUser) watched boards per account.")
                }
            }
            inv.watched = true
            inv.watchInterval = (body.interval == "weekly") ? "weekly" : "daily"
            inv.nextCheckAt = Date().addingTimeInterval(300)
            AuditLogger.log(req: req, action: "investigation_watch_on", target: inv.name)
        } else {
            inv.watched = false
            inv.nextCheckAt = nil
            AuditLogger.log(req: req, action: "investigation_watch_off", target: inv.name)
        }
        try await inv.save(on: req.db)
        return full(inv)
    }

    // MARK: - Helpers

    /// Load the board named by `:id`, enforcing ownership (404 otherwise).
    private func owned(_ req: Request) async throws -> Investigation {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let id = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid investigation ID.")
        }
        guard let inv = try await Investigation.find(id, on: req.db), inv.$user.id == user.id else {
            throw Abort(.notFound)
        }
        return inv
    }

    private static func validName(_ raw: String) throws -> String {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64 else {
            throw Abort(.badRequest, reason: "Name must be 1–64 characters.")
        }
        return name
    }

    /// Must be valid JSON with node/edge arrays and within the size cap.
    private static func validData(_ raw: String) throws -> String {
        guard raw.utf8.count <= maxDataBytes else {
            throw Abort(.payloadTooLarge, reason: "Board is too large (max 512 KB).")
        }
        guard let d = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let nodes = obj["nodes"] as? [[String: Any]],
              let edges = obj["edges"] as? [[String: Any]] else {
            throw Abort(.badRequest, reason: "data must be JSON with `nodes` and `edges` arrays.")
        }
        guard nodes.count <= maxNodes, edges.count <= maxEdges else {
            throw Abort(.payloadTooLarge, reason: "Board exceeds \(maxNodes) nodes or \(maxEdges) edges.")
        }
        guard nodes.allSatisfy({ node in
            guard let id = node["id"] as? String, !id.isEmpty, id.count <= 255 else { return false }
            if let label = node["label"] as? String, label.count > 256 { return false }
            if let type = node["etype"] as? String, type.count > 32 { return false }
            return true
        }), edges.allSatisfy({ edge in
            guard let source = edge["source"] as? String,
                  let target = edge["target"] as? String else { return false }
            return !source.isEmpty && source.count <= 255 && !target.isEmpty && target.count <= 255
        }) else {
            throw Abort(.badRequest, reason: "Board contains an invalid or oversized node/edge.")
        }
        return raw
    }
}
