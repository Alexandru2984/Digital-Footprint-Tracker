import XCTest
@testable import App

final class ExecutiveReportSecurityTests: XCTestCase {
    func testMarkdownTreatsRemoteValuesAsPlainText() {
        let hostile = "<img src=https://tracker.invalid/pixel onerror=alert(1)> [click](https://evil.invalid) | **admin**\n## injected"
        let profile = IdentitySynthesizer.IdentityProfile(
            likelyName: hostile,
            names: [hostile],
            locations: [],
            organizations: [],
            emails: [],
            phones: [],
            handles: [],
            confirmedAccounts: [],
            breaches: [hostile],
            exposedDataClasses: [],
            exposedIPs: [],
            exposedServices: [],
            vulnerabilities: [],
            timeline: [.init(date: "2020-01-01", label: hostile, category: "breach")],
            riskScore: 50,
            riskLevel: "Medium",
            resultCount: 1
        )
        let surface = ExposureDiff.Snapshot(
            portsByIP: [:],
            cvesByIP: [:],
            subdomains: [],
            gradeByDomain: [:]
        )

        let markdown = ExecutiveReport.markdown(
            input: hostile,
            profile: profile,
            surface: surface,
            generatedAt: Date(timeIntervalSince1970: 0)
        )

        XCTAssertFalse(markdown.contains("<img"))
        XCTAssertFalse(markdown.contains("[click](https://evil.invalid)"))
        XCTAssertFalse(markdown.contains("\n## injected"))
        XCTAssertTrue(markdown.contains("&lt;img"))
        XCTAssertTrue(markdown.contains("\\[click\\]\\(https://evil.invalid\\)"))
        XCTAssertTrue(markdown.contains("\\| \\*\\*admin\\*\\* ## injected"))
    }
}
