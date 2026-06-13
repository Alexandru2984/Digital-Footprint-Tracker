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
}
