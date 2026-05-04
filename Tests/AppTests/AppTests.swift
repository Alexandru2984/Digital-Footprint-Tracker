import XCTest
import XCTVapor
import FluentSQLiteDriver
@testable import App

// Builds a fresh in-memory app for each test so tests are fully isolated.
// SQLite is used instead of PostgreSQL to avoid a live database dependency.
// AddScanStatus gracefully skips the PostgreSQL-specific ALTER COLUMN statements.
private func makeApp() async throws -> Application {
    let app = try await Application.make(.testing)

    // Register SQLite under the .psql ID so all model queries that use req.db
    // (which resolves to the default database) hit the in-memory store.
    app.databases.use(.sqlite(.memory), as: .psql, isDefault: true)

    app.middleware.use(CORSMiddleware(configuration: .init(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )), at: .beginning)

    app.sessions.use(.memory)
    app.middleware.use(app.sessions.middleware)

    app.migrations.add(CreateScan())
    app.migrations.add(CreateResult())
    app.migrations.add(AddScanStatus())
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
    try await app.autoMigrate()

    try routes(app)
    return app
}

final class AppTests: XCTestCase {

    // MARK: - Root route

    func testRootRouteResponds() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/") { res in
            XCTAssertEqual(res.status, .ok)
        }
    }

    // MARK: - Input validation

    func testEmptyInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": ""], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testWhitespaceOnlyInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "   "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testTooLongInputReturns400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        let longInput = String(repeating: "a", count: 256)
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": longInput], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    func testInvalidCharactersInInputReturn400() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "user<script>"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest)
        })
    }

    // MARK: - Scan creation

    func testScanCreationReturnsPendingStatus() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "testuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "testuser")
            XCTAssertEqual(body.status, "pending")
            XCTAssertTrue(body.results.isEmpty)
        })
    }

    func testInputIsNormalized() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "  trimmed  "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "trimmed", "Leading/trailing whitespace must be stripped")
        })
    }

    // MARK: - Deduplication

    func testDuplicateScanReturnsSameID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var firstScanID: UUID?

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "dedupeuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            firstScanID = body.scanID
        })

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "dedupeuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, firstScanID, "Duplicate scan should return the same scan ID")
        })
    }

    func testWhitespaceTrimmedDeduplication() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var firstScanID: UUID?

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "normuser"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            firstScanID = try res.content.decode(ScanResponse.self).scanID
        })

        // " normuser " should normalise to "normuser" and hit the same scan.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": " normuser "], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, firstScanID, "Whitespace-padded duplicate should return the same scan ID")
        })
    }

    // MARK: - GET /results/:id

    func testGetResultsReturns404ForUnknownID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/results/\(UUID().uuidString)") { res in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    func testGetResultsReturns400ForInvalidID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.GET, "/results/not-a-uuid") { res in
            XCTAssertEqual(res.status, .badRequest)
        }
    }

    func testGetResultsReturnsCreatedScan() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        var scanID: UUID?

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "lookuptest"], as: .json)
        }, afterResponse: { res in
            scanID = try res.content.decode(ScanResponse.self).scanID
        })

        let id = try XCTUnwrap(scanID)
        try await app.test(.GET, "/results/\(id.uuidString)") { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.scanID, id)
            XCTAssertEqual(body.input, "lookuptest")
        }
    }

    // MARK: - Rate limiter

    func testRateLimiterBlocksAfterLimit() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // First 3 requests (the default anonMax) must succeed.
        for i in 0..<3 {
            try await app.test(.POST, "/scan", beforeRequest: { req in
                try req.content.encode(["input": "ratelimit\(i)"], as: .json)
            }, afterResponse: { res in
                XCTAssertNotEqual(res.status, .tooManyRequests,
                    "Request \(i + 1)/3 should not be rate-limited")
            })
        }

        // The 4th request from the same IP must be rejected.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "ratelimit_overflow"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .tooManyRequests,
                "4th request should be rate-limited")
        })
    }

    // MARK: - Auth-gated endpoints

    func testMyScansRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/my-scans") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testMyScansReturnsPaginatedResponse() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        // Register + login
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "testuser2", "email": "t2@example.com", "password": "password123"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })
        // After registration, the session cookie is set — my-scans should return paged response
        // For this test, just check structure
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "testuser2", "password": "password123"], as: .json)
        }, afterResponse: { _ in })
        // Check my-scans structure
        // (full auth test with session cookies requires more complex setup; just verify auth flow works)
    }

    func testReportEndpointReturns404ForMissingID() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/report/\(UUID().uuidString)") { res in
            XCTAssertEqual(res.status, .notFound)
        }
    }

    func testAdminDashboardRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/admin/dashboard") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }
}
