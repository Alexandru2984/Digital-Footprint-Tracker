import Fluent
import FluentKit

/// The one ordered list of schema migrations, used by the application and by
/// the test suite alike. Tests used to keep their own copy, which drifted:
/// seven migrations were missing from it and a new one was forgotten until a
/// test failed. Migrations that only apply to PostgreSQL check the dialect
/// themselves and are no-ops on the in-memory SQLite the tests use.
enum AppMigrations {
    static func register(on migrations: Migrations) {
        migrations.add(CreateScan())
        migrations.add(CreateResult())
        migrations.add(AddScanStatus())
        // Kept next to the scans table rather than at the end: later data
        // migrations (MigrateSensitiveFieldEncryption) load `Scan` through the
        // model, which selects every field it declares. A database that already
        // ran those simply applies this one as new.
        migrations.add(AddUnavailableSourcesToScans())
        migrations.add(AddResultMetadata())
        migrations.add(CreateScanResultEvents())
        migrations.add(AddInputIndex())
        migrations.add(CreateUser())
        migrations.add(AddUserIDToScans())
        migrations.add(AddWebhookURLToUsers())
        migrations.add(CreateTags())
        migrations.add(CreateScanTags())
        migrations.add(CreateScheduledScans())
        migrations.add(CreateScanNotifications())
        migrations.add(CreateNotificationOutbox())
        migrations.add(CreateExportJobs())
        migrations.add(CreateAPIKeys())
        migrations.add(CreateAuditLogs())
        migrations.add(CreateAuditIntegrityLedger())
        migrations.add(AddRetentionDaysToUsers())
        migrations.add(DefaultUserRetention())
        migrations.add(AddNotificationChannelsToUsers())
        migrations.add(CreateSharedReports())
        migrations.add(HashAPIKeyColumn())
        migrations.add(AddAPIKeyAuthorization())
        migrations.add(HashSharedReportTokens())
        migrations.add(HardenSharedReportLifecycle())
        migrations.add(ExpireLegacySharedReports())
        migrations.add(HardenNotificationLifecycle())
        migrations.add(CreatePluginCache())
        migrations.add(AddVerboseAlertsToUser())
        migrations.add(AddAccountSecurityToUsers())
        migrations.add(AddLastTotpStepToUsers())
        migrations.add(AddInputHashToScans())
        migrations.add(CreateInvestigations())
        migrations.add(AddWatchToInvestigations())
        migrations.add(CreateDarkWebInvestigations())
        migrations.add(EnforceDarkWebActiveJobUniqueness())
        migrations.add(CreateEncryptionMetadata())
        migrations.add(MigrateSensitiveFieldEncryption())
        migrations.add(EncryptTagNames())
        // Session storage table, required by the `.fluent` session driver.
        migrations.add(SessionRecord.migration)
        // Adds created_at to _fluent_sessions so old rows can be pruned (the driver
        // never expires them itself). Must run after SessionRecord.migration.
        migrations.add(AddSessionCreatedAt())
        migrations.add(IndexForeignKeys())
        migrations.add(CascadeScansOnUserDelete())
    }
}
