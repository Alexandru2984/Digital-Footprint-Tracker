import Vapor
import Fluent
import FluentPostgresDriver

public func configure(_ app: Application) async throws {
    // CORS — allow frontend dev from other origins.
    let corsConfig = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfig), at: .beginning)

    // Configure Database
    let databaseHostname = Environment.get("DATABASE_HOST") ?? "localhost"
    let databaseUser = Environment.get("DATABASE_USERNAME") ?? "footprint_user"
    let databasePassword = Environment.get("DATABASE_PASSWORD") ?? "footprint_pass"
    let databaseName = Environment.get("DATABASE_NAME") ?? "footprint_db"

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

    // Run migrations automatically
    try await app.autoMigrate()

    // Register routes
    try routes(app)
}
