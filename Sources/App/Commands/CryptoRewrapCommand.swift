import Vapor

struct CryptoRewrapCommand: AsyncCommand {
    struct Signature: CommandSignature {
        @Option(
            name: "confirm-key-id",
            help: "Must exactly match the active ENCRYPTION_KEY_ID."
        )
        var confirmedKeyID: String?

        @Option(
            name: "batch-size",
            help: "Rows per transaction (1...500, default 100)."
        )
        var batchSize: Int?

        @Option(
            name: "max-batches",
            help: "Stop cleanly after this many checkpointed transactions."
        )
        var maximumBatches: Int?

        @Flag(
            name: "verify-only",
            help: "Authenticate every stored field with the active key without rewriting rows."
        )
        var verifyOnly: Bool

        @Flag(
            name: "restart",
            help: "Discard only the saved cursor and safely process every row again."
        )
        var restart: Bool

        init() {}
    }

    let help = "Re-encrypt and verify all sensitive fields with a resumable active-key checkpoint."

    func run(using context: CommandContext, signature: Signature) async throws {
        guard let confirmedKeyID = signature.confirmedKeyID?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !confirmedKeyID.isEmpty else {
            throw SensitiveFieldRewrapper.Failure.keyIDMismatch(
                active: try TokenEncryption.activeKeyID(),
                confirmed: "missing"
            )
        }
        if signature.verifyOnly && (signature.restart || signature.maximumBatches != nil) {
            throw SensitiveFieldRewrapper.Failure.incompatibleOptions
        }

        let batchSize = signature.batchSize ?? 100
        context.console.info(
            "Sensitive-field \(signature.verifyOnly ? "verification" : "rewrap") starting: key_id=\(confirmedKeyID), batch_size=\(batchSize)"
        )

        let summary: SensitiveFieldRewrapper.Summary
        if signature.verifyOnly {
            summary = try await SensitiveFieldRewrapper.verifyOnly(
                on: context.application.db,
                confirmedKeyID: confirmedKeyID,
                batchSize: batchSize
            )
        } else {
            summary = try await SensitiveFieldRewrapper.run(
                on: context.application.db,
                confirmedKeyID: confirmedKeyID,
                batchSize: batchSize,
                restart: signature.restart,
                maximumBatches: signature.maximumBatches
            )
        }

        let rewritten = summary.rewrittenRows.keys.sorted().map {
            "\($0)=\(summary.rewrittenRows[$0] ?? 0)"
        }.joined(separator: ",")
        let verified = summary.verifiedRows.keys.sorted().map {
            "\($0)=\(summary.verifiedRows[$0] ?? 0)"
        }.joined(separator: ",")
        context.console.print(
            "Sensitive-field progress: completed=\(summary.completed), stage=\(summary.stage.rawValue), phase=\(summary.phase.rawValue), rewritten={\(rewritten)}, verified={\(verified)}"
        )
        if summary.completed {
            context.console.success(
                "Sensitive-field rewrap verified for write_version=\(summary.targetWriteVersion), key_id=\(summary.targetKeyID)."
            )
        } else {
            context.console.warning(
                "Checkpoint saved. Run the same command again to resume before removing any previous key."
            )
        }
    }
}
