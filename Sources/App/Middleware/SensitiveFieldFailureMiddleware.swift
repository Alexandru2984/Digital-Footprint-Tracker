import Vapor

/// Turns authenticated-decryption failures into a bounded, observable request
/// failure. The response never contains a field name, record ID, ciphertext or
/// key detail; operators receive only stable metadata through logs and metrics.
struct SensitiveFieldFailureMiddleware: AsyncMiddleware {
    static let clientReason = "Stored encrypted data is temporarily unavailable."

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        do {
            return try await next.respond(to: request)
        } catch let failure as FieldCrypto.DecryptionFailure {
            await SensitiveFieldFailureReporter.report(
                failure,
                app: request.application,
                context: "request"
            )
            throw Abort(.internalServerError, reason: Self.clientReason)
        }
    }
}

enum SensitiveFieldFailureReporter {
    static func report(
        _ failure: FieldCrypto.DecryptionFailure,
        app: Application,
        context: String
    ) async {
        await MetricsRegistry.shared.recordSensitiveFieldFailure(
            field: failure.field,
            reason: failure.reason
        )
        app.logger.critical("Sensitive encrypted field quarantined from \(context): field=\(failure.field.rawValue) reason=\(failure.reason.rawValue) record_id=\(failure.recordID?.uuidString ?? "unknown")")
    }
}
