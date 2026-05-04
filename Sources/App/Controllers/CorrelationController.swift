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

        guard scans.count >= 2 else {
            return CorrelationResponse(correlations: [], totalScansAnalyzed: scans.count, correlatedEntityCount: 0)
        }

        let patterns: [(type: String, pattern: String)] = [
            ("email",  #"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"#),
            ("ip",     #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#),
            ("domain", #"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|co|uk|de|fr|ru|info|xyz|app|dev)\b"#),
            ("phone",  #"(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}"#),
            ("hash",   #"\b[a-fA-F0-9]{32,64}\b"#),
        ]

        var entityMap: [String: [(scanID: UUID, input: String, source: String, resultType: String)]] = [:]

        for scan in scans {
            guard let scanID = scan.id else { continue }
            for result in scan.results {
                let text = result.rawData
                for (entityType, pattern) in patterns {
                    guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { continue }
                    let range = NSRange(text.startIndex..., in: text)
                    let matches = regex.matches(in: text, range: range)
                    for match in matches {
                        guard let swiftRange = Range(match.range, in: text) else { continue }
                        let entity = String(text[swiftRange]).lowercased()
                        if entity.count < 5 { continue }
                        if entityType == "hash" && entity.allSatisfy({ $0.isNumber }) { continue }
                        entityMap[entity, default: []].append((scanID: scanID, input: scan.input, source: result.source, resultType: result.type))
                    }
                }
            }
        }

        var correlated: [CorrelatedEntity] = []
        for (entity, occurrenceList) in entityMap {
            let uniqueScanIDs = Set(occurrenceList.map { $0.scanID })
            guard uniqueScanIDs.count >= 2 else { continue }

            var seen = Set<UUID>()
            var deduped: [EntityOccurrence] = []
            for occ in occurrenceList {
                if seen.contains(occ.scanID) { continue }
                seen.insert(occ.scanID)
                deduped.append(EntityOccurrence(
                    scanID: occ.scanID.uuidString,
                    input: occ.input,
                    source: occ.source,
                    type: occ.resultType
                ))
            }

            let entityType: String
            if entity.contains("@") { entityType = "email" }
            else if entity.allSatisfy({ $0.isHexDigit }) && entity.count >= 32 { entityType = "hash" }
            else if entity.range(of: #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#, options: .regularExpression) != nil { entityType = "ip" }
            else if entity.hasPrefix("+") || entity.first?.isNumber == true { entityType = "phone" }
            else { entityType = "domain" }

            correlated.append(CorrelatedEntity(entity: entity, entityType: entityType, occurrences: deduped))
        }

        correlated.sort { $0.occurrences.count > $1.occurrences.count }
        let limited = Array(correlated.prefix(100))

        return CorrelationResponse(
            correlations: limited,
            totalScansAnalyzed: scans.count,
            correlatedEntityCount: limited.count
        )
    }
}
