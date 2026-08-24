import Vapor

/// Runs a bounded full-chain verification at boot and every five minutes.
/// Metrics expose the last result; failures are deliberately loud but do not
/// take the API offline, preserving incident access to the admin evidence.
actor AuditIntegrityMonitor: LifecycleHandler {
    private var task: Task<Void, Never>?
    private let intervalNanoseconds: UInt64

    init(intervalSeconds: UInt64 = 300) {
        self.intervalNanoseconds = max(30, intervalSeconds) * 1_000_000_000
    }

    nonisolated func didBoot(_ application: Application) throws {
        guard application.auditIntegrityConfiguration != nil else {
            application.logger.notice("[AuditIntegrity] Monitor disabled without a signing key.")
            return
        }
        let app = application
        Task { await self.start(app: app) }
    }

    nonisolated func shutdown(_ application: Application) {
        Task { await self.stop() }
    }

    private func start(app: Application) {
        guard task == nil else { return }
        task = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.verify(app: app)
                try? await Task.sleep(nanoseconds: self.intervalNanoseconds)
            }
        }
    }

    private func stop() {
        task?.cancel()
        task = nil
    }

    private func verify(app: Application) async {
        guard let configuration = app.auditIntegrityConfiguration else { return }
        do {
            let result = try await AuditIntegrityLedger.verify(
                on: app.db,
                configuration: configuration
            )
            await MetricsRegistry.shared.recordAuditIntegrityVerification(result)
            if !result.isValid {
                app.logger.critical(
                    "[AuditIntegrity] Verification failed (code=\(result.failureCode ?? "unknown"))."
                )
            }
        } catch {
            app.logger.error("[AuditIntegrity] Verification could not complete.")
        }
    }
}
