import Vapor
import Fluent
import Foundation

struct CorrelationController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("correlations", use: getCorrelations)
    }

    struct EntityOccurrence: Content {
        let scanID: String
        let input: String
        let source: String
        let type: String
    }

    struct CorrelatedEntity: Content {
        let entity: String
        let entityType: String
        let occurrences: [EntityOccurrence]
    }

    struct CorrelationResponse: Content {
        let correlations: [CorrelatedEntity]
        let totalScansAnalyzed: Int
        let correlatedEntityCount: Int
    }

    @Sendable
    func getCorrelations(req: Request) async throws -> CorrelationResponse {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized)
        }

        let scans = try await Scan.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .filter(\.$statusRaw == "completed")
            .with(\.$results)
            .all()

        // Build DB-free summaries and run the pure correlation core. It draws
        // entities from the scan input + each result's structured metadata
        // (falling back to regex over rawData for unmigrated plugins).
        let summaries = scans.compactMap { scan -> Correlator.ScanSummary? in
            guard let id = scan.id else { return nil }
            return Correlator.ScanSummary(
                id: id,
                input: scan.input,
                results: scan.results.map {
                    Correlator.ResultEntry(source: $0.source, type: $0.type, rawData: $0.rawData, metadata: $0.metadataObject)
                }
            )
        }

        let entities = Correlator.correlate(summaries)
        let correlations = entities.map { entity in
            CorrelatedEntity(
                entity: entity.value,
                entityType: entity.type,
                occurrences: entity.occurrences.map {
                    EntityOccurrence(scanID: $0.scanID.uuidString, input: $0.input, source: $0.source, type: $0.resultType)
                }
            )
        }

        return CorrelationResponse(
            correlations: correlations,
            totalScansAnalyzed: scans.count,
            correlatedEntityCount: correlations.count
        )
    }
}
