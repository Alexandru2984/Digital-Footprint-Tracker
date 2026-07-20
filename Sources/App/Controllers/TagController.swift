import Vapor
import Fluent
import SQLKit

struct TagController: RouteCollection {
    static let maxTagsPerUser = 50
    static let maxTagsPerScan = 20

    func boot(routes: RoutesBuilder) throws {
        let guarded = routes.grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 5, authedMax: 120, windowSeconds: 60))
        let tags = guarded.grouped("tags")
        tags.get(use: listTags)
        tags.post(use: createTag)
        tags.group(":id") { tag in
            tag.delete(use: deleteTag)
            tag.get("scans", use: scansByTag)
        }
        // Attach/detach tags on a scan
        guarded.grouped("scans", ":scanID", "tags").post(":tagID", use: addTagToScan)
        guarded.grouped("scans", ":scanID", "tags").delete(":tagID", use: removeTagFromScan)
        guarded.grouped("scans", ":scanID", "tags").get(use: tagsForScan)
    }

    // MARK: - User's tags
    @Sendable
    func listTags(req: Request) async throws -> [TagDTO] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let tags = try await Tag.query(on: req.db).filter(\.$user.$id == user.id!).all()
        return tags.map(TagDTO.init)
    }

    @Sendable
    func createTag(req: Request) async throws -> TagDTO {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        struct Body: Content { var name: String; var colour: String }
        let body = try req.content.decode(Body.self)
        let name = body.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 32, name.utf8.count <= 128,
              name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw Abort(.badRequest, reason: "Tag name must be 1–32 characters.")
        }
        // Strict #RRGGBB hex check — without it, the field accepts any string
        // and could end up rendered inline (e.g. style="background: <colour>")
        // by future UI changes, opening a CSS-injection vector.
        let colour = body.colour.lowercased()
        guard colour.range(of: "^#[0-9a-f]{6}$", options: .regularExpression) != nil else {
            throw Abort(.badRequest, reason: "Colour must be a 6-digit hex string (e.g. #10b981).")
        }
        let tag = Tag(userID: user.id!, name: name, colour: colour)
        try await req.db.transaction { database in
            if let sql = database as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM users WHERE id = \(bind: user.id!) FOR UPDATE").run()
            }
            let existingTags = try await Tag.query(on: database)
                .filter(\.$user.$id == user.id!)
                .all()
            guard existingTags.count < Self.maxTagsPerUser else {
                throw Abort(.tooManyRequests, reason: "Maximum \(Self.maxTagsPerUser) tags per account.")
            }
            guard !existingTags.contains(where: {
                $0.name.caseInsensitiveCompare(name) == .orderedSame
            }) else {
                throw Abort(.conflict, reason: "A tag with that name already exists.")
            }
            try await tag.save(on: database)
        }
        await AuditLogger.log(req: req, action: "tag_created", target: name)
        return TagDTO(tag: tag)
    }

    @Sendable
    func deleteTag(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let tagID = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let tag = try await Tag.find(tagID, on: req.db), tag.$user.id == user.id else { throw Abort(.notFound) }
        let name = tag.name
        try await tag.delete(on: req.db)
        await AuditLogger.log(req: req, action: "tag_deleted", target: name)
        return .noContent
    }

    @Sendable
    func scansByTag(req: Request) async throws -> [String] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let tagID = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let tag = try await Tag.find(tagID, on: req.db), tag.$user.id == user.id else { throw Abort(.notFound) }
        try await tag.$scans.load(on: req.db)
        return tag.scans
            .filter { $0.$user.id == user.id }
            .compactMap { $0.id?.uuidString }
    }

    // MARK: - Scan ↔ Tag relationship
    @Sendable
    func tagsForScan(req: Request) async throws -> [TagDTO] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let scanIDStr = req.parameters.get("scanID"), let scanID = UUID(uuidString: scanIDStr) else { throw Abort(.badRequest) }
        guard let scan = try await Scan.find(scanID, on: req.db), scan.$user.id == user.id else { throw Abort(.notFound) }
        try await scan.$tags.load(on: req.db)
        return scan.tags.filter { $0.$user.id == user.id }.map(TagDTO.init)
    }

    @Sendable
    func addTagToScan(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let scanIDStr = req.parameters.get("scanID"), let scanID = UUID(uuidString: scanIDStr),
              let tagIDStr  = req.parameters.get("tagID"),  let tagID  = UUID(uuidString: tagIDStr)
        else { throw Abort(.badRequest) }
        guard let scan = try await Scan.find(scanID, on: req.db), scan.$user.id == user.id else { throw Abort(.notFound) }
        guard let tag  = try await Tag.find(tagID,  on: req.db), tag.$user.id  == user.id else { throw Abort(.notFound) }
        try await req.db.transaction { database in
            if let sql = database as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM scans WHERE id = \(bind: scanID) FOR UPDATE").run()
            }
            let existing = try await ScanTag.query(on: database)
                .filter(\.$scan.$id == scanID).filter(\.$tag.$id == tagID).first()
            if existing == nil {
                let associationCount = try await ScanTag.query(on: database)
                    .filter(\.$scan.$id == scanID)
                    .count()
                guard associationCount < Self.maxTagsPerScan else {
                    throw Abort(.tooManyRequests, reason: "Maximum \(Self.maxTagsPerScan) tags per scan.")
                }
                try await ScanTag(scanID: scan.id!, tagID: tag.id!).save(on: database)
            }
        }
        return .created
    }

    @Sendable
    func removeTagFromScan(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let scanIDStr = req.parameters.get("scanID"), let scanID = UUID(uuidString: scanIDStr),
              let tagIDStr  = req.parameters.get("tagID"),  let tagID  = UUID(uuidString: tagIDStr)
        else { throw Abort(.badRequest) }
        guard let scan = try await Scan.find(scanID, on: req.db), scan.$user.id == user.id else { throw Abort(.notFound) }
        guard let tag = try await Tag.find(tagID, on: req.db), tag.$user.id == user.id else { throw Abort(.notFound) }
        try await ScanTag.query(on: req.db)
            .filter(\.$scan.$id == scan.id!).filter(\.$tag.$id == tagID).delete()
        return .noContent
    }
}

struct TagDTO: Content {
    let id: String
    let name: String
    let colour: String
    init(tag: Tag) {
        self.id = tag.id?.uuidString ?? ""
        self.name = tag.name
        self.colour = tag.colour
    }
}
