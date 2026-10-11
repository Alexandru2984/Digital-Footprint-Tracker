import Vapor
import Fluent

extension Scan {
    /// Authorizes read access to a scan's results / identity / export.
    ///
    /// - **Owned scan** (created while logged in): the owner only.
    /// - **Ownerless scan** (created anonymously): readable by anyone holding its
    ///   unguessable 122-bit `scanID` — capability access, the same model as a
    ///   share link. This lets logged-out users see their own results without
    ///   making every anonymous scan admin-only (which locked them out entirely).
    ///   Want a scan kept private? Create it while signed in.
    func authorizeRead(_ req: Request) async throws {
        guard let ownerID = self.$user.id else { return } // anonymous → capability
        guard let user = try await req.currentUser(), user.id == ownerID else {
            throw Abort(.forbidden, reason: "Access denied.")
        }
    }

    /// The scan named by route parameter `name`, with its results, already
    /// through `authorizeRead`. Every results-reading handler starts here, so
    /// none can load a scan and forget to authorize it.
    static func readableWithResults(_ req: Request, parameter name: String = "id") async throws -> Scan {
        guard let raw = req.parameters.get(name), let id = UUID(uuidString: raw) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == id)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        try await scan.authorizeRead(req)
        return scan
    }
}
