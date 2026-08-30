import Vapor

/// Requires a recently-authenticated administrator for every route it guards.
///
/// The admin handlers already perform this check themselves, and all of them do
/// it correctly. The problem is that it was only ever a convention: the admin
/// surface spans two controllers — `AdminController` and `UserController`'s
/// `/admin/scans` — so "every admin handler remembers the guard" is a property
/// nobody enforced, and a seventh route added elsewhere would depend on its
/// author noticing the pattern.
///
/// The two controls are deliberately kept side by side rather than one replacing
/// the other. The middleware covers a handler that forgets its own check; the
/// handler check covers a route registered outside this group. Neither is
/// redundant, because each fails in the case the other cannot see.
struct AdminMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let user = try await request.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }
        return try await next.respond(to: request)
    }
}
