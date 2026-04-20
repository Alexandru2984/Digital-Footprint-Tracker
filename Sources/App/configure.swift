import Vapor
import Fluent
import FluentPostgresDriver

public func configure(_ app: Application) async throws {
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
        allowedMethods: [.GET, .POST, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfig), at: .beginning)

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
    app.migrations.add(AddInputIndex())

    // Run migrations automatically
    try await app.autoMigrate()

    // Register routes
    try routes(app)
}
