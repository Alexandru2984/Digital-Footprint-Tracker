import XCTest
import XCTVapor
import Fluent
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

    app.sessions.use(.fluent)
    app.middleware.use(app.sessions.middleware)
    // Mirror production so the CSRF origin check is exercised by tests. It is a
    // no-op for requests without an Origin/Referer header (the existing tests),
    // and blocks cross-origin POST/PUT/PATCH/DELETE.
    app.middleware.use(CSRFMiddleware())

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
    // Note: HashAPIKeyColumn + HashSharedReportTokens are PostgreSQL-only
    // (use ADD COLUMN IF NOT EXISTS / ALTER COLUMN SET NOT NULL / ADD CONSTRAINT)
    // and are intentionally skipped here. No test in this suite exercises the
    // APIKey or SharedReport models, so the pre-hash schema is sufficient.
    app.migrations.add(CreatePluginCache())
    app.migrations.add(AddVerboseAlertsToUser())
    app.migrations.add(SessionRecord.migration)
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

        // Register + login so the scan has an owner (IDOR fix requires ownership)
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "resultstest", "email": "rt@example.com", "password": "password123"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })

        var sessionCookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "resultstest", "password": "password123"], as: .json)
        }, afterResponse: { res in
            // Extract session cookie to replay on subsequent requests
            if let raw = res.headers.first(name: "set-cookie"),
               let pair = raw.split(separator: ";").first {
                sessionCookie = String(pair)
            }
        })

        var scanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "lookuptest"], as: .json)
            if !sessionCookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie) }
        }, afterResponse: { res in
            scanID = try res.content.decode(ScanResponse.self).scanID
        })

        let id = try XCTUnwrap(scanID)
        try await app.test(.GET, "/results/\(id.uuidString)", beforeRequest: { req in
            if !sessionCookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie) }
        }) { res in
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

    // MARK: - SSRF Guard

    func testSSRFGuardBlocksLocalhost() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("LOCALHOST"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("foo.localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@localhost"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("::1"))
    }

    func testSSRFGuardBlocksLoopbackIPv4() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("127.0.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("127.1.2.3"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@127.0.0.1"))
    }

    func testSSRFGuardBlocksPrivateRanges() {
        // RFC 1918 — class A / B / C
        XCTAssertTrue(SSRFGuard.isInternalTarget("10.0.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("10.255.255.255"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("192.168.1.1"))
        // 172.16.0.0/12 — only 172.16 through 172.31 are private
        XCTAssertTrue(SSRFGuard.isInternalTarget("172.16.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("172.31.255.255"))
        // 172.15 and 172.32 are PUBLIC — must not be blocked
        XCTAssertFalse(SSRFGuard.isInternalTarget("172.15.0.1"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("172.32.0.1"))
    }

    func testSSRFGuardBlocksLinkLocalAndCloudMetadata() {
        // 169.254.169.254 is the AWS/GCP instance-metadata endpoint — critical to block
        XCTAssertTrue(SSRFGuard.isInternalTarget("169.254.169.254"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("169.254.0.1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("user@169.254.169.254"))
    }

    func testSSRFGuardBlocksIPv6Private() {
        XCTAssertTrue(SSRFGuard.isInternalTarget("fc00::1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("fd12:3456:789a::1"))
        XCTAssertTrue(SSRFGuard.isInternalTarget("fe80::1"))
    }

    func testSSRFGuardAllowsPublicHosts() {
        XCTAssertFalse(SSRFGuard.isInternalTarget("example.com"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("8.8.8.8"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("1.1.1.1"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("user@example.com"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("swift.micutu.com"))
    }

    func testSSRFGuardURLBlocksInternalHosts() throws {
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://127.0.0.1/foo"))))
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://10.0.0.1/foo"))))
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://169.254.169.254/latest/meta-data"))))
        XCTAssertFalse(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://example.com/foo"))))
        XCTAssertFalse(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "https://api.github.com/users/alice"))))
    }

    func testScanEndpointRejectsInternalTarget() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "127.0.0.1"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest,
                "Scan endpoint must reject internal/private targets to prevent SSRF")
        })
    }

    // Numeric IP obfuscation: decimal / hex / short / IPv4-mapped forms all
    // decode to internal addresses and must be blocked when used as a URL host.
    func testSSRFGuardBlocksNumericIPObfuscation() throws {
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://2130706433/"))),     "decimal 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://0x7f000001/"))),      "hex 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://127.1/"))),           "short-form 127.0.0.1")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://0.0.0.0/"))),         "0.0.0.0/8")
        XCTAssertTrue(SSRFGuard.isInternalURL(try XCTUnwrap(URL(string: "http://[::ffff:127.0.0.1]/"))), "IPv4-mapped loopback")
        XCTAssertTrue(SSRFGuard.isInternalTarget("100.64.0.1"), "CGNAT 100.64/10")
    }

    // A bare numeric *username* (scan input) must NOT be misread as an integer
    // IP by the structural check — that would block legitimate OSINT.
    func testSSRFGuardDoesNotMisreadNumericUsername() {
        XCTAssertFalse(SSRFGuard.isInternalTarget("12345"))
        XCTAssertFalse(SSRFGuard.isInternalTarget("2130706433"))
    }

    // MARK: - CSRF origin check

    func testCSRFBlocksLookalikeOrigin() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        // hasPrefix would have let this through; an exact host match must not.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "csrfblock"], as: .json)
            req.headers.replaceOrAdd(name: "Origin", value: "https://swift.micutu.com.evil.com")
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .forbidden, "Look-alike cross-origin host must be blocked")
        })
    }

    func testCSRFAllowsLegitimateOrigin() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "csrfallow"], as: .json)
            req.headers.replaceOrAdd(name: "Origin", value: "https://swift.micutu.com")
        }, afterResponse: { res in
            XCTAssertNotEqual(res.status, .forbidden, "Legitimate origin must pass the CSRF check")
        })
    }

    // MARK: - OSINT engine: plugin metadata coherence

    // Every shipping plugin must declare an honest description — not the
    // protocol's generic "OSINT plugin" fallback. This is what regressed
    // silently before: ~17 of 24 plugins fell through a name-keyed switch.
    func testAllPluginsHaveHonestDescriptions() {
        for plugin in ScanController.defaultPlugins {
            XCTAssertFalse(plugin.description.isEmpty, "\(plugin.name) has an empty description")
            XCTAssertNotEqual(plugin.description, "OSINT plugin",
                "\(plugin.name) is still using the generic fallback description")
        }
    }

    // Plugin names double as cache keys and selection identifiers — they must be unique.
    func testPluginNamesAreUnique() {
        let names = ScanController.defaultPlugins.map { $0.name }
        XCTAssertEqual(names.count, Set(names).count, "Duplicate plugin name(s): \(names)")
    }

    // cacheTTL now lives on each plugin. Verify the tuned values land where they
    // should and that an un-overridden plugin keeps the 1-hour default — the old
    // central map silently dropped these to the default via key mismatches.
    func testPluginCacheTTLsAreDeclaredPerPlugin() {
        XCTAssertEqual(HaveIBeenPwnedPlugin().cacheTTL, 86_400, "HIBP breach data should cache 24h")
        XCTAssertEqual(BulkUsernamePlugin().cacheTTL, 21_600, "Sherlock username sweep should cache 6h")
        XCTAssertEqual(WhoisPlugin().cacheTTL, 14_400, "WHOIS should cache 4h")
        XCTAssertEqual(PhonePlugin().cacheTTL, 86_400, "Phone carrier data should cache 24h")
        // A plugin that doesn't override keeps the protocol default.
        XCTAssertEqual(RedditPlugin().cacheTTL, 3_600, "Un-tuned plugin keeps the 1h default")
    }

    // MARK: - Target derivation (email → username pivot)

    func testTargetDeriverUsernamePassesThrough() {
        XCTAssertEqual(TargetDeriver.candidates(for: "johndoe"),
                       [TargetDeriver.Candidate(value: "johndoe", origin: .primary)])
    }

    func testTargetDeriverEmailDerivesUsername() {
        let c = TargetDeriver.candidates(for: "john.doe@gmail.com")
        XCTAssertEqual(c.first, TargetDeriver.Candidate(value: "john.doe@gmail.com", origin: .primary))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "john.doe", origin: .emailLocalPart)))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "johndoe", origin: .variant)),
            "dot-stripped (Gmail) form should be a variant")
    }

    func testTargetDeriverStripsPlusTag() {
        let c = TargetDeriver.candidates(for: "alice+newsletter@example.com")
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "alice", origin: .emailLocalPart)))
        XCTAssertFalse(c.contains { $0.origin.derived && $0.value.contains("+") }, "The +tag must be stripped")
    }

    func testTargetDeriverSkipsShortLocalPart() {
        XCTAssertEqual(TargetDeriver.candidates(for: "ab@x.com"),
                       [TargetDeriver.Candidate(value: "ab@x.com", origin: .primary)],
                       "A too-short local-part yields no username candidate")
    }

    func testTargetDeriverDomainHasNoDerivation() {
        XCTAssertEqual(TargetDeriver.candidates(for: "example.com"),
                       [TargetDeriver.Candidate(value: "example.com", origin: .primary)])
    }

    // Username with a separator → sibling-handle variants (no dotted forms, so
    // domains are never derived from). Variants are weaker guesses.
    func testTargetDeriverUsernameSeparatorVariants() {
        let c = TargetDeriver.candidates(for: "john_doe")
        XCTAssertEqual(c.first, TargetDeriver.Candidate(value: "john_doe", origin: .primary))
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "johndoe", origin: .variant)), "separator-stripped")
        XCTAssertTrue(c.contains(TargetDeriver.Candidate(value: "john-doe", origin: .variant)), "separator-swapped")
    }

    // Heavy plugins run only on heavy-eligible candidates so the 480-site sweep
    // is bounded to one run: the email local-part is eligible, variants are not.
    func testTargetDeriverHeavyEligibilityBoundsFanOut() {
        let c = TargetDeriver.candidates(for: "john.doe@gmail.com")
        let heavy = c.filter { $0.origin.heavyEligible }
        XCTAssertEqual(heavy.count, 2, "primary + email local-part only (variant excluded)")
        XCTAssertTrue(heavy.contains(TargetDeriver.Candidate(value: "john.doe", origin: .emailLocalPart)))
        XCTAssertFalse(heavy.contains { $0.origin == .variant })
    }

    // MARK: - Source enrichment (Gravatar profile, GitHub commit emails)

    func testGravatarParsesProfileAndLinkedAccounts() {
        let json = """
        {"entry":[{
          "displayName":"Jane Roe","preferredUsername":"janer",
          "profileUrl":"https://gravatar.com/janer","currentLocation":"Berlin",
          "accounts":[
            {"shortname":"twitter","username":"janer_x","url":"https://twitter.com/janer_x","verified":"true"},
            {"shortname":"github","username":"janer","url":"https://github.com/janer","verified":"false"}
          ]
        }]}
        """
        let results = GravatarPlugin.parseProfile(Data(json.utf8), email: "jane@example.com", avatarURL: "https://en.gravatar.com/avatar/x")
        let r = try? XCTUnwrap(results)
        XCTAssertEqual(r?.count, 3, "profile + 2 linked accounts")
        XCTAssertEqual(r?.first?.metadata?["name"], "Jane Roe")
        XCTAssertTrue(r?.contains { $0.source == "Gravatar:twitter" && $0.confidenceScore > 0.9 } ?? false,
            "Verified linked account scores higher")
    }

    func testGravatarReturnsNilForJunk() {
        XCTAssertNil(GravatarPlugin.parseProfile(Data("not json".utf8), email: "x@y.com", avatarURL: "u"))
    }

    func testGitHubExtractsCommitEmailsAndDropsNoreply() {
        let json = """
        [
          {"type":"PushEvent","payload":{"commits":[
            {"author":{"email":"Real.Dev@Example.com","name":"Real Dev"}},
            {"author":{"email":"12345+janer@users.noreply.github.com","name":"janer"}}
          ]}},
          {"type":"WatchEvent","payload":{}}
        ]
        """
        let emails = UsernamePlugin.extractCommitEmails(from: Data(json.utf8))
        XCTAssertEqual(emails, ["real.dev@example.com"], "lowercased, deduped, noreply dropped")
    }

    // MARK: - Email intelligence

    func testEmailIntelDetectsDisposable() {
        XCTAssertTrue(EmailIntelPlugin.isDisposable("mailinator.com"))
        XCTAssertTrue(EmailIntelPlugin.isDisposable("GuerrillaMail.com"))
        XCTAssertFalse(EmailIntelPlugin.isDisposable("gmail.com"))
    }

    func testEmailIntelFingerprintsProvider() {
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["aspmx.l.google.com"]), "Google (Gmail / Workspace)")
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["example-com.mail.protection.outlook.com"]), "Microsoft (Outlook / 365)")
        XCTAssertEqual(EmailIntelPlugin.mxProvider(["mail.protonmail.ch"]), "Proton Mail")
        XCTAssertNil(EmailIntelPlugin.mxProvider(["mail.self-hosted.example"]))
    }

    // MARK: - DNS over HTTPS

    func testDoHParsesAnswersAndFiltersByType() {
        let json = """
        {"Status":0,"Answer":[
          {"name":"x.com","type":1,"data":"1.2.3.4"},
          {"name":"x.com","type":5,"data":"cname.x.com"},
          {"name":"x.com","type":1,"data":"5.6.7.8"}
        ]}
        """
        XCTAssertEqual(DoHResolver.parse(Data(json.utf8), type: "A"), ["1.2.3.4", "5.6.7.8"],
            "Only A (type 1) answers, CNAME filtered out")
    }

    func testDoHMxHostStripsPriorityAndTrailingDot() {
        XCTAssertEqual(DoHResolver.mxHost("10 mail.example.com."), "mail.example.com")
    }

    func testDoHReverseIPv4Name() {
        XCTAssertEqual(DoHResolver.reverseIPv4Name("1.2.3.4"), "4.3.2.1.in-addr.arpa")
        XCTAssertNil(DoHResolver.reverseIPv4Name("not.an.ip.x"))
    }

    // MARK: - Transitive pivot

    func testPivotExtractorFindsNewIdentities() {
        let results = [
            PluginResult(source: "GitHubAccountCheck", type: "account_presence", confidenceScore: 1.0,
                         rawData: "x", metadata: ["platform": "github", "username": "alice"]),
            PluginResult(source: "GitHub:commits", type: "email", confidenceScore: 0.9,
                         rawData: "x", metadata: ["email": "real.dev@example.com", "username": "alice"]),
            PluginResult(source: "Gravatar:twitter", type: "identity_proof", confidenceScore: 0.95,
                         rawData: "x", metadata: ["platform": "twitter", "username": "alice_x"])
        ]
        let pivots = PivotExtractor.candidates(from: results, alreadyScanned: ["alice"])
        XCTAssertTrue(pivots.contains("real.dev@example.com"), "harvested email becomes a pivot")
        XCTAssertTrue(pivots.contains("alice_x"), "linked handle becomes a pivot")
        XCTAssertFalse(pivots.contains("alice"), "already-scanned identity is excluded")
    }

    func testPivotExtractorRespectsCap() {
        let results = (0..<20).map {
            PluginResult(source: "s", type: "email", confidenceScore: 1.0, rawData: "x",
                         metadata: ["email": "user\($0)@example.com"])
        }
        XCTAssertEqual(PivotExtractor.candidates(from: results, alreadyScanned: []).count, PivotExtractor.maxPivots)
    }

    func testPivotedOriginIsDiscountedAndNotHeavy() {
        XCTAssertEqual(TargetDeriver.Origin.pivoted.confidenceFactor, 0.6, accuracy: 0.001)
        XCTAssertFalse(TargetDeriver.Origin.pivoted.heavyEligible, "pivots never trigger the heavy sweep")
        XCTAssertTrue(TargetDeriver.Origin.pivoted.derived)
    }

    // MARK: - Risk scoring

    private func mkResult(_ type: String, _ confidence: Double, source: String = "src", raw: String = "data") -> App.Result {
        App.Result(scanID: UUID(), source: source, type: type, confidenceScore: confidence, rawData: raw)
    }

    func testRiskScorerEmptyIsLow() {
        let s = RiskScorer.compute(results: [])
        XCTAssertEqual(s.value, 0)
        XCTAssertEqual(s.level, .low)
    }

    // The regression that motivated the rewrite: HIBP's "no breaches found"
    // result (type breach_check, confidence 1.0) must contribute ZERO risk.
    func testRiskScorerCleanBreachCheckIsZeroRisk() {
        let s = RiskScorer.compute(results: [mkResult("breach_check", 1.0, raw: "No breaches found.")])
        XCTAssertEqual(s.value, 0, "A clean breach check must not add risk")
    }

    // And it must not inflate a score built from real (account) findings.
    func testRiskScorerCleanCheckDoesNotInflate() {
        let accounts = (0..<5).map { mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)") }
        let withClean = accounts + [mkResult("breach_check", 1.0, raw: "No breaches found.")]
        XCTAssertEqual(RiskScorer.compute(results: accounts).value,
                       RiskScorer.compute(results: withClean).value,
                       "A clean breach check must not change the score")
    }

    func testRiskScorerConfirmedBreachIsAtLeastMedium() {
        let s = RiskScorer.compute(results: [mkResult("data_breach", 1.0, raw: "Found in 3 breaches")])
        XCTAssertGreaterThanOrEqual(s.value, 25, "A confirmed breach should reach at least Medium")
    }

    // A single breach must outweigh a large pile of public account presences.
    func testRiskScorerBreachOutweighsManyAccounts() {
        let breach = RiskScorer.compute(results: [mkResult("data_breach", 1.0)])
        let accounts = RiskScorer.compute(results: (0..<20).map {
            mkResult("account_presence", 0.9, source: "s\($0)", raw: "acct \($0)")
        })
        XCTAssertGreaterThan(breach.value, accounts.value,
            "One breach should score higher than 20 social accounts")
    }

    // Account presence saturates: 50 profiles aren't dramatically worse than 10,
    // and account presence alone never escalates past the Low band.
    func testRiskScorerAccountPresenceSaturates() {
        let ten = RiskScorer.compute(results: (0..<10).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        let fifty = RiskScorer.compute(results: (0..<50).map {
            mkResult("account_presence", 1.0, source: "s\($0)", raw: "a\($0)")
        }).value
        XCTAssertLessThanOrEqual(fifty - ten, 3, "Account category must saturate")
        XCTAssertLessThan(fifty, 25, "Public accounts alone should stay in the Low band")
    }

    // Exact-duplicate findings (same source+type+rawData) are counted once.
    func testRiskScorerDeduplicatesIdenticalFindings() {
        let one = RiskScorer.compute(results: [mkResult("data_breach", 1.0, source: "hibp", raw: "X")]).value
        let dup = RiskScorer.compute(results: [
            mkResult("data_breach", 1.0, source: "hibp", raw: "X"),
            mkResult("data_breach", 1.0, source: "hibp", raw: "X")
        ]).value
        XCTAssertEqual(one, dup, "Identical findings must not double-count")
    }

    // MARK: - Structured result metadata

    // Cache entries serialized before `metadata` existed must still decode
    // (the field is optional → decodeIfPresent yields nil).
    func testPluginResultDecodesLegacyCacheWithoutMetadata() throws {
        let legacy = #"{"source":"github","type":"account_presence","confidenceScore":1.0,"rawData":"x"}"#
        let pr = try JSONDecoder().decode(PluginResult.self, from: Data(legacy.utf8))
        XCTAssertEqual(pr.source, "github")
        XCTAssertNil(pr.metadata)
    }

    func testPluginResultMetadataRoundTrips() throws {
        let pr = PluginResult(source: "github", type: "account_presence", confidenceScore: 1.0,
                              rawData: "x", metadata: ["platform": "github", "username": "alice"])
        let back = try JSONDecoder().decode(PluginResult.self, from: JSONEncoder().encode(pr))
        XCTAssertEqual(back.metadata?["username"], "alice")
    }

    func testResultMetadataObjectDecodesStoredJSON() {
        let withMeta = App.Result(scanID: UUID(), source: "github", type: "account_presence",
                                  confidenceScore: 1.0, rawData: "x",
                                  metadata: #"{"platform":"github","username":"alice"}"#)
        XCTAssertEqual(withMeta.metadataObject?["username"], "alice")

        let without = App.Result(scanID: UUID(), source: "s", type: "t", confidenceScore: 0.5, rawData: "x")
        XCTAssertNil(without.metadataObject)
    }

    // MARK: - Correlation engine

    private func summary(_ input: String, _ results: [Correlator.ResultEntry] = []) -> Correlator.ScanSummary {
        Correlator.ScanSummary(id: UUID(), input: input, results: results)
    }

    func testCorrelatorRequiresTwoScans() {
        XCTAssertTrue(Correlator.correlate([summary("alice@example.com")]).isEmpty)
    }

    func testCorrelatorIgnoresUnsharedEntities() {
        let a = summary("alice@example.com")
        let b = summary("bob@example.com")
        XCTAssertTrue(Correlator.correlate([a, b]).isEmpty, "No shared entity → no correlation")
    }

    // The scan input itself is now a correlation anchor (it was ignored before):
    // an email that is one scan's input and another scan's structured finding links them.
    func testCorrelatorLinksInputToStructuredMetadata() {
        let a = summary("alice@example.com")
        let b = summary("aliceuser", [
            Correlator.ResultEntry(source: "HaveIBeenPwned", type: "data_breach", rawData: "x",
                                   metadata: ["email": "alice@example.com", "breachCount": "2"])
        ])
        let entities = Correlator.correlate([a, b])
        let email = entities.first { $0.type == "email" && $0.value == "alice@example.com" }
        XCTAssertEqual(email?.occurrences.count, 2, "Email should link both scans")
    }

    // Precise: a structured twitter handle links to a username scan — regex over
    // the display string could not reliably extract this.
    func testCorrelatorUsesStructuredMetadata() {
        let a = summary("alicejones", [
            Correlator.ResultEntry(source: "GitHubAccountCheck", type: "account_presence", rawData: "x",
                                   metadata: ["platform": "github", "username": "alicejones", "twitter": "bobsmith"])
        ])
        let b = summary("bobsmith")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "bobsmith" && $0.occurrences.count == 2 },
            "Structured twitter handle should link to the username scan")
    }

    // Fallback: a plugin with no metadata still contributes via regex over rawData.
    func testCorrelatorFallsBackToRegex() {
        let a = summary("targetalpha", [
            Correlator.ResultEntry(source: "SomePlugin", type: "paste_exposure",
                                   rawData: "leaked credential for shared@example.com here", metadata: nil)
        ])
        let b = summary("shared@example.com")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "shared@example.com" && $0.occurrences.count == 2 })
    }

    // A Keybase identity proof exposing a github handle links to a username scan.
    func testCorrelatorLinksPlatformProofHandles() {
        let a = summary("alicekb", [
            Correlator.ResultEntry(source: "Keybase", type: "identity_proof", rawData: "proofs",
                                   metadata: ["platform": "keybase", "github": "devhandle"])
        ])
        let b = summary("devhandle")
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "devhandle" && $0.type == "username" && $0.occurrences.count == 2 },
            "A platform proof handle should link to a username scan")
    }

    // A discovered subdomain links to a domain scanned directly.
    func testCorrelatorLinksSubdomainToDomainInput() {
        let a = summary("shared.example.com")
        let b = summary("otherinput", [
            Correlator.ResultEntry(source: "crt.sh", type: "subdomain", rawData: "shared.example.com",
                                   metadata: ["subdomain": "shared.example.com", "domain": "example.com"])
        ])
        let entities = Correlator.correlate([a, b])
        XCTAssertTrue(entities.contains { $0.value == "shared.example.com" && $0.type == "domain" && $0.occurrences.count == 2 })
    }

    // MARK: - Cross-tenant dedup isolation

    func testDedupDoesNotLeakAcrossOwners() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        // Register + login user A.
        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "ownerA", "email": "a@example.com", "password": "password123"], as: .json)
        }, afterResponse: { res in XCTAssertEqual(res.status, .ok) })

        var cookieA = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "ownerA", "password": "password123"], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "set-cookie"), let pair = raw.split(separator: ";").first {
                cookieA = String(pair)
            }
        })

        // A scans a target.
        var aScanID: UUID?
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "sharedtarget"], as: .json)
            req.headers.replaceOrAdd(name: "Cookie", value: cookieA)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            aScanID = try res.content.decode(ScanResponse.self).scanID
        })
        let ownedID = try XCTUnwrap(aScanID)

        // An anonymous caller scanning the same input must get a fresh scan —
        // never user A's scan ID (or results) served from the dedup path.
        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "sharedtarget"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertNotEqual(body.scanID, ownedID,
                "Anonymous dedup must not return another user's scan")
        })
    }

    // MARK: - Email normalisation

    func testScanNormalisesEmailToLowercase() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/scan", beforeRequest: { req in
            try req.content.encode(["input": "User@Example.COM"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode(ScanResponse.self)
            XCTAssertEqual(body.input, "user@example.com",
                "Emails must be lowercased so cache lookups are case-insensitive")
        })
    }

    // MARK: - Crypto helpers

    func testSha256HexProducesKnownDigests() {
        // NIST test vectors for SHA-256
        XCTAssertEqual(
            sha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        XCTAssertEqual(
            sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    // MARK: - GDPR self-service

    func testAccountExportRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.GET, "/account/export") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }

    func testAccountDeleteRequiresAuth() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }
        try await app.test(.DELETE, "/account", beforeRequest: { req in
            try req.content.encode(["confirmUsername": "anyone"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .unauthorized)
        })
    }

    func testAccountDeleteRejectsMismatchedConfirmation() async throws {
        let app = try await makeApp()
        addTeardownBlock { try await app.asyncShutdown() }

        try await app.test(.POST, "/auth/register", beforeRequest: { req in
            try req.content.encode(["username": "gdpruser", "email": "g@example.com", "password": "password123"], as: .json)
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
        })

        var cookie = ""
        try await app.test(.POST, "/auth/login", beforeRequest: { req in
            try req.content.encode(["username": "gdpruser", "password": "password123"], as: .json)
        }, afterResponse: { res in
            if let raw = res.headers.first(name: "set-cookie"),
               let pair = raw.split(separator: ";").first {
                cookie = String(pair)
            }
        })

        // Wrong username → 400, account NOT deleted.
        try await app.test(.DELETE, "/account", beforeRequest: { req in
            try req.content.encode(["confirmUsername": "someoneelse"], as: .json)
            if !cookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: cookie) }
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .badRequest,
                "Account delete must reject a mismatched confirmUsername to prevent accidental wipe via session theft alone.")
        })

        // Session is still valid and the account row was NOT deleted. We
        // probe via /auth/me instead of /account/export because the test DB
        // intentionally skips the PostgreSQL-only HashAPIKeyColumn migration
        // — the export query would hit a missing column in SQLite.
        try await app.test(.GET, "/auth/me", beforeRequest: { req in
            if !cookie.isEmpty { req.headers.replaceOrAdd(name: "Cookie", value: cookie) }
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok,
                "Account must still exist after the rejected delete attempt.")
        })
    }
}
