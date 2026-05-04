import Vapor
import Fluent

struct HealthController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("health", use: health)
        routes.get("metrics", use: metrics)
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
