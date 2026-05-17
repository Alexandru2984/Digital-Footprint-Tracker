import Vapor
import Fluent
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct HealthController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("health", use: health)
        routes.get("metrics", use: metrics)
        // Registered at /geolocate (not /api/geolocate) — nginx strips the /api/
        // prefix when forwarding, so the public URL remains /api/geolocate.
        // Rate-limited to prevent abuse: this endpoint forwards request bodies
        // to ip-api.com on the server's behalf.
        routes.grouped(ScanRateLimiter(anonMax: 5, authedMax: 30, windowSeconds: 60))
            .post("geolocate", use: geolocate)
    }

    /// Server-side proxy to ip-api.com/batch.
    ///
    /// Hardened against abuse:
    ///   • Authentication required — prevents anonymous abuse of the server as
    ///     an open HTTP proxy and protects the project's ip-api.com quota.
    ///   • 4 KB body cap — ip-api batch accepts up to 100 IPs; well under 4 KB.
    ///   • JSON-array structural check — rejects garbage / oversized payloads
    ///     before forwarding upstream.
    @Sendable func geolocate(req: Request) async throws -> Response {
        guard try await req.currentUser() != nil else {
            throw Abort(.unauthorized, reason: "Authentication required.")
        }
        guard let bodyData = req.body.data else {
            throw Abort(.badRequest, reason: "Request body required.")
        }
        guard bodyData.readableBytes <= 4096 else {
            throw Abort(.payloadTooLarge, reason: "Body must be ≤ 4 KB.")
        }
        let bodyBytes = Data(bodyData.readableBytesView)
        guard let json = try? JSONSerialization.jsonObject(with: bodyBytes),
              json is [Any] else {
            throw Abort(.badRequest, reason: "Body must be a JSON array.")
        }

        var urlReq = URLRequest(url: URL(string: "http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,isp,org,query")!)
        urlReq.httpMethod = "POST"
        urlReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlReq.httpBody = bodyBytes
        urlReq.timeoutInterval = 10

        let (data, _) = try await URLSession.shared.data(for: urlReq)
        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "application/json")]),
            body: .init(data: data)
        )
    }

    @Sendable func health(req: Request) async throws -> Response {
        let dbOk: Bool
        do {
            _ = try await User.query(on: req.db).count()
            dbOk = true
        } catch {
            dbOk = false
        }

        let payload: [String: Any] = [
            "status": dbOk ? "ok" : "degraded",
            "db": dbOk ? "ok" : "error",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted)
        return Response(
            status: dbOk ? .ok : .serviceUnavailable,
            headers: HTTPHeaders([("Content-Type", "application/json")]),
            body: .init(data: data)
        )
    }

    @Sendable func metrics(req: Request) async throws -> Response {
        guard let user = try await req.currentUser(), user.isAdmin else {
            throw Abort(.forbidden)
        }

        let totalScans = (try? await Scan.query(on: req.db).count()) ?? 0
        let totalUsers = (try? await User.query(on: req.db).count()) ?? 0
        let totalResults = (try? await App.Result.query(on: req.db).count()) ?? 0
        let completedScans = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "completed").count()) ?? 0
        let failedScans = (try? await Scan.query(on: req.db).filter(\.$statusRaw == "failed").count()) ?? 0
        let scheduledScans = (try? await ScheduledScan.query(on: req.db).filter(\.$isActive == true).count()) ?? 0

        let yesterday = Date().addingTimeInterval(-86400)
        let scansLast24h = (try? await Scan.query(on: req.db).filter(\.$createdAt >= yesterday).count()) ?? 0

        let payload: [String: Any] = [
            "totalScans": totalScans,
            "completedScans": completedScans,
            "failedScans": failedScans,
            "scansLast24h": scansLast24h,
            "totalUsers": totalUsers,
            "totalResults": totalResults,
            "activeScheduledScans": scheduledScans,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted)
        return Response(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "application/json")]),
            body: .init(data: data)
        )
    }
}
