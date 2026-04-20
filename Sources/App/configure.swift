import Vapor
import Fluent
import FluentPostgresDriver

public func configure(_ app: Application) async throws {
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

    // Run migrations automatically
    try await app.autoMigrate()

    // Register routes
    try routes(app)
}
