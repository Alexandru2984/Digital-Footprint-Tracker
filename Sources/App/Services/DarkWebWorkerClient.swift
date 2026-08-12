import AsyncHTTPClient
import Crypto
import Foundation
import Vapor

struct DarkWebFinding: Codable, Sendable, Equatable {
    let type: String
    let value: String
    let source: String
    let confidence: Double
    let firstSeen: String?
    let lastSeen: String?
}

struct DarkWebRelationship: Codable, Sendable, Equatable {
    let source: String
    let target: String
    let type: String
    let confidence: Double
}

struct DarkWebWorkerResult: Codable, Sendable, Equatable {
    let schemaVersion: Int
    let status: String
    let findings: [DarkWebFinding]
    let relationships: [DarkWebRelationship]
    let sources: [String]
}

enum DarkWebWorkerClient {
    enum ClientError: Error {
        case configuration
        case transport
        case authentication
        case invalidResponse
        case workerRejected
        case deadline

        var failureCode: String {
            switch self {
            case .configuration: return "worker_configuration"
            case .transport: return "worker_unavailable"
            case .authentication: return "worker_authentication"
            case .invalidResponse: return "invalid_worker_response"
            case .workerRejected: return "worker_rejected"
            case .deadline: return "worker_timeout"
            }
        }
    }

    struct RequestPayload: Codable, Sendable {
        let jobID: String
        let target: String
        let targetKind: String
        let depth: String
        let useTor: Bool
        let useLLM: Bool
    }

    static let maximumResponseBytes = 512 * 1_024
    static let maximumFindings = 250
    static let maximumRelationships = 500

    static func execute(
        jobID: UUID,
        target: String,
        targetKind: DarkWebTargetKind,
        configuration: DarkWebConfiguration,
        on app: Application
    ) async throws -> DarkWebWorkerResult {
        guard configuration.enabled,
              let baseURL = configuration.workerURL,
              let secret = configuration.sharedSecret,
              let endpoint = URL(string: "/v1/investigations", relativeTo: baseURL)?.absoluteURL else {
            throw ClientError.configuration
        }

        let payload = RequestPayload(
            jobID: jobID.uuidString,
            target: target,
            targetKind: targetKind.rawValue,
            depth: "shallow",
            useTor: true,
            useLLM: false
        )
        let body = try JSONEncoder().encode(payload)
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let signature = sign(
            timestamp: timestamp,
            method: "POST",
            path: "/v1/investigations",
            body: body,
            secret: secret
        )

        var request = HTTPClientRequest(url: endpoint.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/json")
        request.headers.add(name: "X-DFT-Timestamp", value: timestamp)
        request.headers.add(name: "X-DFT-Signature", value: signature)
        request.body = .bytes(body)

        let response: HTTPClientResponse
        do {
            response = try await app.http.client.shared.execute(
                request,
                timeout: .seconds(Int64(configuration.jobTimeoutSeconds))
            )
        } catch let error as HTTPClientError where error == .deadlineExceeded {
            throw ClientError.deadline
        } catch {
            throw ClientError.transport
        }

        switch Int(response.status.code) {
        case 200: break
        case 401, 403: throw ClientError.authentication
        case 408, 504: throw ClientError.deadline
        default: throw ClientError.workerRejected
        }

        let responseBody: Data
        do {
            let buffer = try await response.body.collect(upTo: maximumResponseBytes)
            responseBody = Data(buffer.readableBytesView)
        } catch {
            throw ClientError.invalidResponse
        }

        let result: DarkWebWorkerResult
        do { result = try JSONDecoder().decode(DarkWebWorkerResult.self, from: responseBody) }
        catch { throw ClientError.invalidResponse }
        return try validate(result, originalTarget: target)
    }

    static func cancel(
        jobID: UUID,
        configuration: DarkWebConfiguration,
        on app: Application
    ) async throws {
        guard configuration.enabled,
              let baseURL = configuration.workerURL,
              let secret = configuration.sharedSecret else {
            throw ClientError.configuration
        }
        let path = "/v1/investigations/\(jobID.uuidString)/cancel"
        guard let endpoint = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw ClientError.configuration
        }
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let body = Data()
        let signature = sign(
            timestamp: timestamp, method: "POST", path: path, body: body, secret: secret
        )
        var request = HTTPClientRequest(url: endpoint.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Length", value: "0")
        request.headers.add(name: "X-DFT-Timestamp", value: timestamp)
        request.headers.add(name: "X-DFT-Signature", value: signature)
        let response: HTTPClientResponse
        do { response = try await app.http.client.shared.execute(request, timeout: .seconds(5)) }
        catch { throw ClientError.transport }
        guard [200, 202, 404].contains(Int(response.status.code)) else {
            throw ClientError.workerRejected
        }
    }

    static func validate(
        _ result: DarkWebWorkerResult,
        originalTarget: String
    ) throws -> DarkWebWorkerResult {
        guard result.schemaVersion == 1,
              result.status == "completed",
              result.findings.count <= maximumFindings,
              result.relationships.count <= maximumRelationships,
              result.sources.count <= 64 else {
            throw ClientError.invalidResponse
        }

        func safeText(_ value: String, maxBytes: Int) -> Bool {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty
                && trimmed.utf8.count <= maxBytes
                && trimmed.unicodeScalars.allSatisfy {
                    !CharacterSet.controlCharacters.contains($0)
                }
        }
        func safeDate(_ value: String?) -> Bool {
            guard let value else { return true }
            return value.range(of: #"^\d{4}(-\d{2}(-\d{2})?)?$"#,
                               options: .regularExpression) != nil
        }

        guard safeText(originalTarget, maxBytes: 255),
              result.sources.allSatisfy({ safeText($0, maxBytes: 80) }),
              result.findings.allSatisfy({ finding in
                  safeText(finding.type, maxBytes: 64)
                    && safeText(finding.value, maxBytes: 512)
                    && safeText(finding.source, maxBytes: 80)
                    && finding.confidence.isFinite
                    && (0...1).contains(finding.confidence)
                    && safeDate(finding.firstSeen)
                    && safeDate(finding.lastSeen)
              }),
              result.relationships.allSatisfy({ relationship in
                  safeText(relationship.source, maxBytes: 512)
                    && safeText(relationship.target, maxBytes: 512)
                    && safeText(relationship.type, maxBytes: 64)
                    && relationship.confidence.isFinite
                    && (0...1).contains(relationship.confidence)
              }) else {
            throw ClientError.invalidResponse
        }

        // Persist only the normalized schema above. Page bodies, context
        // snippets, scraped URLs and worker filesystem paths are intentionally
        // absent from the contract and cannot cross this trust boundary.
        return result
    }

    static func sign(
        timestamp: String,
        method: String,
        path: String,
        body: Data,
        secret: String
    ) -> String {
        var message = Data(timestamp.utf8)
        message.append(0x0A)
        message.append(Data(method.uppercased().utf8))
        message.append(0x0A)
        message.append(Data(path.utf8))
        message.append(0x0A)
        message.append(body)
        let mac = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: Data(secret.utf8))
        )
        return mac.map { String(format: "%02x", $0) }.joined()
    }
}
