import Vapor
import Fluent
import FluentPostgresDriver
#if canImport(Glibc)
import Glibc
#endif

public func configure(_ app: Application) async throws {
    // Prevent SIGPIPE from crashing the server when a client disconnects
    // mid-write (common on Linux with long-lived connections).
    signal(SIGPIPE, SIG_IGN)

    // A live deployment must never persist sensitive fields in plaintext merely
    // because ENCRYPTION_KEY is absent or malformed. Validate before connecting,
    // migrating, seeding, or serving any request.
    try TokenEncryption.validateConfiguration(required: app.environment == .production)
    // CORS — in production restrict to the real origin; allow all only during development.
    let allowedOrigin: CORSMiddleware.AllowOriginSetting
    if app.environment == .production {
        let origin = Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com"
        allowedOrigin = .custom(origin)
    } else {
        allowedOrigin = .all
    }
    let corsConfig = CORSMiddleware.Configuration(
        allowedOrigin: allowedOrigin,
        allowedMethods: [.GET, .POST, .OPTIONS, .DELETE, .PUT],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfig), at: .beginning)

    // Sessions persisted to PostgreSQL via Fluent so they survive process
    // restarts and don't bloat heap memory under sustained traffic. The
    // SessionRecord migration is registered alongside the rest below.
    app.sessions.use(.fluent)
    app.sessions.configuration.cookieFactory = { sessionID in
        var cookie = HTTPCookies.Value(string: sessionID.string)
        cookie.isSecure = true
        cookie.isHTTPOnly = true
        cookie.sameSite = .strict
        return cookie
    }
    app.middleware.use(app.sessions.middleware)
    app.middleware.use(APIKeyMiddleware())
    app.middleware.use(CSRFMiddleware())

    // Global HTTP client timeout — applies to all outbound requests (all plugins).
    var clientConfig = app.http.client.configuration
    clientConfig.timeout = .init(connect: .seconds(5), read: .seconds(15))
    app.http.client.configuration = clientConfig

    // Crash early in production if the password secret is missing — never fall
    // back to a hardcoded credential in a live environment.
    let databaseHostname = Environment.get("DATABASE_HOST") ?? "localhost"
    let databaseUser     = Environment.get("DATABASE_USERNAME") ?? "footprint_user"
    let databaseName     = Environment.get("DATABASE_NAME") ?? "footprint_db"
    let databasePassword: String
    if let pw = Environment.get("DATABASE_PASSWORD") {
        databasePassword = pw
    } else if app.environment == .production {
        fatalError("DATABASE_PASSWORD environment variable must be set in production.")
    } else {
        app.logger.warning("DATABASE_PASSWORD not set — using insecure default (development only)")
        databasePassword = "footprint_pass"
    }

    app.databases.use(.postgres(
        hostname: databaseHostname,
        username: databaseUser,
        password: databasePassword,
        database: databaseName
    ), as: .psql)

    // Register migrations
    app.migrations.add(CreateScan())
    app.migrations.add(CreateResult())
    app.migrations.add(AddScanStatus())
    app.migrations.add(AddResultMetadata())
    app.migrations.add(AddInputIndex())
    app.migrations.add(CreateUser())
    app.migrations.add(AddUserIDToScans())
    app.migrations.add(AddWebhookURLToUsers())
    app.migrations.add(CreateTags())
    app.migrations.add(CreateScanTags())
    app.migrations.add(CreateScheduledScans())
    app.migrations.add(CreateScanNotifications())
    app.migrations.add(CreateAPIKeys())
    app.migrations.add(CreateAuditLogs())
    app.migrations.add(AddRetentionDaysToUsers())
    app.migrations.add(AddNotificationChannelsToUsers())
    app.migrations.add(CreateSharedReports())
    app.migrations.add(HashAPIKeyColumn())
    app.migrations.add(HashSharedReportTokens())
    app.migrations.add(CreatePluginCache())
    app.migrations.add(AddVerboseAlertsToUser())
    app.migrations.add(AddAccountSecurityToUsers())
    app.migrations.add(AddInputHashToScans())
    app.migrations.add(CreateInvestigations())
    app.migrations.add(AddWatchToInvestigations())
    app.migrations.add(CreateEncryptionMetadata())
    app.migrations.add(MigrateSensitiveFieldEncryption())
    // Session storage table — required by `.fluent` session driver above.
    app.migrations.add(SessionRecord.migration)
    // Adds created_at to _fluent_sessions so old rows can be pruned (the driver
    // never expires them itself). Must run after SessionRecord.migration.
    app.migrations.add(AddSessionCreatedAt())

    // Run migrations automatically
    try await app.autoMigrate()
    try await EncryptionKeyVerifier.verifyOrInitialize(on: app.db)

    // Seed admin user from environment variables if not already present.
    let adminUsername = Environment.get("ADMIN_USERNAME") ?? "admin"
    let adminEmail = Environment.get("ADMIN_EMAIL") ?? "admin@localhost"
    if let adminPassword = Environment.get("ADMIN_PASSWORD") {
        // .first_where targets Swift collections; this is a Fluent DB query
        // where .filter(...).first() is the canonical async lookup pattern.
        // swiftlint:disable:next first_where
        let existing = try await User.query(on: app.db).filter(\.$username == adminUsername).first()
        if existing == nil {
            let hash = try await app.password.async.hash(adminPassword)
            let admin = User(username: adminUsername, email: adminEmail, passwordHash: hash, isAdmin: true, emailVerified: true)
            try await admin.save(on: app.db)
            app.logger.notice("Admin user '\(adminUsername)' created.")
        }
    } else {
        app.logger.warning("ADMIN_PASSWORD not set — admin account will not be seeded.")
    }

    // Load the offline GeoIP database once at boot (privacy: /api/geolocate
    // resolves IPs from a local file instead of proxying them to a third party).
    app.geoIP = GeoIP.open(app: app)

    // Register routes
    try routes(app)

    // Periodic cleanup: delete scans older than 30 days.
    // Runs daily using a detached background task with a sleep loop.
    // The task is tied to app lifetime via a lifecycle handler.
    app.lifecycle.use(ScanCleanupLifecycle())
    app.lifecycle.use(ScheduledScanRunner())
    app.lifecycle.use(InvestigationWatchRunner())
}
