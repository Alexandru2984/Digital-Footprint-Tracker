import Vapor

/// Adds `Cache-Control: no-store` to every response so OSINT data is never
/// cached by browsers, proxies, or CDN edge nodes.
struct NoCacheMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }
}
