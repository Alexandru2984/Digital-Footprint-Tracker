import Vapor
import Fluent

struct TagController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let tags = routes.grouped("tags")
        tags.get(use: listTags)
        tags.post(use: createTag)
        tags.group(":id") { tag in
            tag.delete(use: deleteTag)
            tag.get("scans", use: scansByTag)
        }
        // Attach/detach tags on a scan
        routes.grouped("scans", ":scanID", "tags").post(":tagID", use: addTagToScan)
        routes.grouped("scans", ":scanID", "tags").delete(":tagID", use: removeTagFromScan)
        routes.grouped("scans", ":scanID", "tags").get(use: tagsForScan)
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
        guard !name.isEmpty, name.count <= 32 else {
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
        try await tag.save(on: req.db)
        return TagDTO(tag: tag)
    }

    @Sendable
    func deleteTag(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let tagID = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let tag = try await Tag.find(tagID, on: req.db), tag.$user.id == user.id else { throw Abort(.notFound) }
        try await tag.delete(on: req.db)
        return .noContent
    }

    @Sendable
    func scansByTag(req: Request) async throws -> [String] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let tagID = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let tag = try await Tag.find(tagID, on: req.db), tag.$user.id == user.id else { throw Abort(.notFound) }
        try await tag.$scans.load(on: req.db)
        return tag.scans.compactMap { $0.id?.uuidString }
    }

    // MARK: - Scan ↔ Tag relationship
    @Sendable
    func tagsForScan(req: Request) async throws -> [TagDTO] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let scanIDStr = req.parameters.get("scanID"), let scanID = UUID(uuidString: scanIDStr) else { throw Abort(.badRequest) }
        guard let scan = try await Scan.find(scanID, on: req.db), scan.$user.id == user.id else { throw Abort(.notFound) }
        try await scan.$tags.load(on: req.db)
        return scan.tags.map(TagDTO.init)
    }

    @Sendable
    func addTagToScan(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let scanIDStr = req.parameters.get("scanID"), let scanID = UUID(uuidString: scanIDStr),
              let tagIDStr  = req.parameters.get("tagID"),  let tagID  = UUID(uuidString: tagIDStr)
        else { throw Abort(.badRequest) }
        guard let scan = try await Scan.find(scanID, on: req.db), scan.$user.id == user.id else { throw Abort(.notFound) }
        guard let tag  = try await Tag.find(tagID,  on: req.db), tag.$user.id  == user.id else { throw Abort(.notFound) }
        let existing = try await ScanTag.query(on: req.db)
            .filter(\.$scan.$id == scanID).filter(\.$tag.$id == tagID).first()
        if existing == nil {
            try await ScanTag(scanID: scan.id!, tagID: tag.id!).save(on: req.db)
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
