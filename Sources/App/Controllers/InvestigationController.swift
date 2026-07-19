import Vapor
import Fluent

/// CRUD for saved investigation boards (the persistent, growing relationship
/// graphs built in the graph UI). All endpoints are owner-scoped: a board is only
/// ever visible to the user who created it.
struct InvestigationController: RouteCollection {
    /// Hard cap on a serialized board so a runaway client can't store megabytes.
    private static let maxDataBytes = 512 * 1024

    func boot(routes: RoutesBuilder) throws {
        let inv = routes.grouped("investigations")
        inv.get(use: list)
        inv.post(use: create)
        inv.group(":id") { one in
            one.get(use: get)
            one.put(use: update)
            one.delete(use: remove)
        }
    }

    // MARK: - DTOs

    struct Summary: Content {
        let id: String
        let name: String
        let nodeCount: Int
        let updatedAt: Double?
    }
    struct Full: Content {
        let id: String
        let name: String
        let data: String          // graph JSON, plaintext
        let createdAt: Double?
        let updatedAt: Double?
    }

    private func summary(_ inv: Investigation) -> Summary {
        Summary(id: inv.id?.uuidString ?? "", name: inv.name,
                nodeCount: Self.nodeCount(inv.data),
                updatedAt: inv.updatedAt?.timeIntervalSince1970)
    }
    private func full(_ inv: Investigation) -> Full {
        Full(id: inv.id?.uuidString ?? "", name: inv.name, data: inv.data,
             createdAt: inv.createdAt?.timeIntervalSince1970,
             updatedAt: inv.updatedAt?.timeIntervalSince1970)
    }

    /// Count nodes without trusting the client — parse the stored JSON.
    private static func nodeCount(_ json: String) -> Int {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nodes = obj["nodes"] as? [Any] else { return 0 }
        return nodes.count
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
              obj["nodes"] is [Any], obj["edges"] is [Any] else {
            throw Abort(.badRequest, reason: "data must be JSON with `nodes` and `edges` arrays.")
        }
        return raw
    }
}
