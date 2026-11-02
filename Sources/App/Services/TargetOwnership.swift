import Fluent
import Vapor

/// Which targets an account has proven it controls, and what that unlocks.
///
/// Most checks read public records and run on anyone's target. A few go
/// further (`FootprintPlugin.requiresOwnership`): they fetch files that may
/// hold credentials from the target's own server, or test an address against
/// sign-up flows on many services. Those run only on a target the account owns:
///
/// - the account's own address, once the account's email is verified;
/// - an address proven with a code mailed to it;
/// - a domain proven with a DNS TXT record or a file on the site, which also
///   covers its subdomains and every address at it.
///
/// Full scans of other people's targets are allowed but bounded per day
/// (`dailyThirdPartyFullScans`); past that, a scan of someone else's target
/// runs the light checks only.
enum TargetOwnership {
    /// Full (heavy) scans of targets the account has not proven it controls,
    /// per rolling 24 hours, before further ones are run light.
    static let dailyThirdPartyFullScans = 25
    /// Claims per account, proven or pending.
    static let maxClaims = 50
    /// Unproven claims per account at a time.
    static let maxPending = 5
    /// How long a mailed code stays valid.
    static let codeLifetime: TimeInterval = 15 * 60
    /// How long a domain token stays valid before it must be requested again.
    static let tokenLifetime: TimeInterval = 7 * 24 * 3600
    /// Wrong codes allowed per mailed code.
    static let maxAttempts = 5
    /// Codes mailed per claim, ever; and the gap between two of them.
    static let maxSends = 5
    static let resendInterval: TimeInterval = 60

    struct Claim: Equatable, Sendable {
        let kind: VerifiedTarget.Kind
        let value: String
    }

    private static let domainPattern =
        #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"#

    /// The claim `raw` would make: a normalized address or domain, or nil for
    /// anything else (usernames, phone numbers and IPs cannot be proven).
    static func claim(_ raw: String) -> Claim? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.contains("@") {
            guard let email = EmailAddress.normalize(trimmed), let domain = domain(ofEmail: email),
                  isDomain(domain) else { return nil }
            return Claim(kind: .email, value: email)
        }
        var domain = trimmed
        if domain.hasSuffix(".") { domain.removeLast() }
        guard isDomain(domain) else { return nil }
        return Claim(kind: .domain, value: domain)
    }

    static func isDomain(_ value: String) -> Bool {
        value.utf8.count <= 253 && value.range(of: domainPattern, options: .regularExpression) != nil
    }

    static func domain(ofEmail email: String) -> String? {
        guard let at = email.lastIndex(of: "@") else { return nil }
        let domain = String(email[email.index(after: at)...])
        return domain.isEmpty ? nil : domain
    }

    /// Whether a proven `claim` covers the scan `input`: an address covers
    /// itself; a domain covers itself, its subdomains, and addresses at either.
    static func covers(_ claim: Claim, input: String) -> Bool {
        guard let target = Self.claim(input) else { return false }
        switch (claim.kind, target.kind) {
        case (.email, .email):
            return claim.value == target.value
        case (.email, .domain):
            return false
        case (.domain, .email):
            guard let host = domain(ofEmail: target.value) else { return false }
            return host == claim.value || host.hasSuffix("." + claim.value)
        case (.domain, .domain):
            return target.value == claim.value || target.value.hasSuffix("." + claim.value)
        }
    }

    /// The claims that would cover `input`, most specific first: the address
    /// itself, then its domain and each parent domain. Looked up by blind
    /// index, so nothing is decrypted to answer.
    static func coveringClaims(for input: String) -> [Claim] {
        guard let target = claim(input) else { return [] }
        var claims: [Claim] = []
        var host: String
        switch target.kind {
        case .email:
            claims.append(target)
            guard let domain = domain(ofEmail: target.value) else { return claims }
            host = domain
        case .domain:
            host = target.value
        }
        while host.contains(".") {
            claims.append(Claim(kind: .domain, value: host))
            host = String(host[host.index(after: host.firstIndex(of: ".")!)...])
        }
        return claims
    }

    /// Whether `user` has proven control of `input`.
    static func isOwned(input: String, by user: User?, on db: Database) async throws -> Bool {
        guard let user, let userID = user.id, user.emailVerified else { return false }
        let covering = coveringClaims(for: input)
        guard !covering.isEmpty else { return false }
        if let own = EmailAddress.normalize(user.email), covering.contains(Claim(kind: .email, value: own)) {
            return true
        }
        let hashes = covering.flatMap { FieldCrypto.blindIndexCandidates($0.value) }
        let proven = try await VerifiedTarget.query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$valueHash ~~ hashes)
            .filter(\.$verifiedAt != nil)
            .all()
        // The blind index matched; confirm on the decrypted value and kind, so
        // a claimed address can never pass for a domain of the same spelling.
        return proven.contains { row in
            guard let value = try? row.value else { return false }
            return covering.contains(Claim(kind: row.kind, value: value))
        }
    }

    /// The checks a scan runs and the ones withheld from it.
    struct Plan {
        let plugins: [any FootprintPlugin]
        /// Names of the plugins that would have run on `input` but will not.
        let skipped: [String]
        let owned: Bool
        /// True when heavy plugins were dropped because the daily allowance
        /// of full scans on other people's targets is used up.
        let throttled: Bool
    }

    /// Splits `plugins` into what runs on `input` and what is withheld: the
    /// ownership-only checks when the target is not owned, and every heavy
    /// check when `heavyAllowed` is false. Only checks that could act on the
    /// input are listed as skipped.
    static func plan(
        _ plugins: [any FootprintPlugin], input: String, owned: Bool, heavyAllowed: Bool = true
    ) -> Plan {
        var run: [any FootprintPlugin] = []
        var withheld: [any FootprintPlugin] = []
        for plugin in plugins {
            if (plugin.requiresOwnership && !owned) || (plugin.heavy && !heavyAllowed) {
                withheld.append(plugin)
            } else {
                run.append(plugin)
            }
        }
        let skipped = ScanPluginRunner.applicablePlugins(withheld, for: input).map(\.name)
        let throttled = !heavyAllowed && withheld.contains(where: \.heavy)
        return Plan(plugins: run, skipped: skipped, owned: owned, throttled: throttled)
    }

    /// Why `skipped` checks were withheld, as `ScanResponse.skipReason` names
    /// it: `daily_limit` when a heavy check that needs no proof is among them
    /// (only the daily allowance withholds those), otherwise `ownership`.
    static func skipReason(for skipped: [String]) -> String? {
        guard !skipped.isEmpty else { return nil }
        let names = Set(skipped)
        let throttled = ScanController.defaultPlugins.contains {
            names.contains($0.name) && $0.heavy && !$0.requiresOwnership
        }
        return throttled ? "daily_limit" : "ownership"
    }

    /// Whether `user` may still run a full scan on a target it does not own
    /// today: fewer than `dailyThirdPartyFullScans` such scans in 24 hours.
    static func thirdPartyFullScanAllowed(for user: User, on db: Database) async throws -> Bool {
        guard let userID = user.id else { return false }
        let since = Date().addingTimeInterval(-24 * 3600)
        let count = try await Scan.query(on: db)
            .filter(\.$user.$id == userID)
            .filter(\.$thirdParty == true)
            .filter(\.$createdAt >= since)
            .count()
        return count < dailyThirdPartyFullScans
    }

    /// The plan for recurring work (scheduled scans, watched boards): the
    /// light checks, with the ownership-only ones only when `owner` has proven
    /// the target. A proven domain also gets `monitoredDomainChecks`: its
    /// attack surface is what its owner monitors it for. Recurring scans do
    /// not count toward the daily allowance.
    static func backgroundPlan(input: String, owner: User?, on db: Database) async -> Plan {
        let owned = (try? await isOwned(input: input, by: owner, on: db)) ?? false
        var plugins = ScanController.backgroundPlugins
        if owned, claim(input)?.kind == .domain {
            plugins += monitoredDomainChecks
        }
        return plan(plugins, input: input, owned: owned)
    }

    /// The heavy checks that act on a domain (attack surface, exposed files,
    /// lookalikes). On a schedule they run only for a domain the owner has
    /// proven, at most daily; never the username sweeps, and never for a
    /// proven address, which does not make its domain the account's.
    static var monitoredDomainChecks: [any FootprintPlugin] {
        ScanController.defaultPlugins.filter { $0.heavy && $0.accepts == [.domain] }
    }

    /// The plan for an interactive or bulk scan by `user` (nil when anonymous):
    /// owned targets get every eligible check; others lose the ownership-only
    /// checks, and the heavy ones too once the daily allowance is spent.
    static func plan(
        _ plugins: [any FootprintPlugin], input: String, user: User?, on db: Database
    ) async throws -> Plan {
        let owned = try await isOwned(input: input, by: user, on: db)
        guard !owned, let user, plugins.contains(where: \.heavy) else {
            return plan(plugins, input: input, owned: owned)
        }
        let heavyAllowed = try await thirdPartyFullScanAllowed(for: user, on: db)
        return plan(plugins, input: input, owned: false, heavyAllowed: heavyAllowed)
    }
}

// MARK: - Proof of control

extension TargetOwnership {
    /// Where a domain owner publishes the token: a TXT record at the label
    /// below (or at the apex), or this file on the site.
    static let txtLabel = "_dft-verify"
    static let txtPrefix = "dft-verify="
    static let wellKnownPath = "/.well-known/dft-verify.txt"

    /// A fresh random token for a domain claim: 128 bits, hex.
    static func newToken() -> String {
        var generator = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &generator)) }.joined()
    }

    /// A fresh six-digit code for an address claim.
    static func newCode() -> String {
        var generator = SystemRandomNumberGenerator()
        return String(format: "%06d", Int.random(in: 0...999_999, using: &generator))
    }

    /// What is stored for a mailed code: a hash salted with the claim's ID, so
    /// equal codes on two claims never share a stored value.
    static func codeDigest(_ code: String, claimID: UUID) -> String {
        sha256Hex("\(claimID.uuidString):\(code)")
    }

    /// Whether `records` (TXT strings) contain the token.
    static func txtMatches(_ records: [String], token: String) -> Bool {
        let expected = txtPrefix + token
        return records.contains { record in
            // A long TXT value arrives as several quoted chunks; join them.
            let joined = record.replacingOccurrences(of: "\" \"", with: "")
                .trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            return joined == expected
        }
    }

    /// Whether a served verification file holds the token, alone or as the
    /// `dft-verify=` line.
    static func fileMatches(_ body: String, token: String) -> Bool {
        body.split(whereSeparator: \.isNewline).contains { line in
            let value = line.trimmingCharacters(in: .whitespaces)
            return value == token || value == txtPrefix + token
        }
    }

    /// How control of a domain was shown, or nil when it was not.
    typealias DomainProbe = @Sendable (_ domain: String, _ token: String, _ app: Application) async -> String?

    /// Looks for the token in DNS (`_dft-verify.<domain>`, then the apex) and
    /// then on the site over HTTPS. Redirects are not followed: the proof has
    /// to come from the domain itself.
    static let liveDomainProbe: DomainProbe = { domain, token, app in
        for name in ["\(txtLabel).\(domain)", domain]
        where txtMatches(await DoHResolver.resolve(name, type: "TXT", on: app), token: token) {
            return "dns_txt"
        }
        guard let url = URL(string: "https://\(domain)\(wellKnownPath)"),
              let response = await PluginHTTP.request(
                url, headers: ["Accept": "text/plain"], timeout: 10, maxRetries: 0,
                bodyMode: .complete(maxBytes: 4 * 1_024), on: app
              ), response.status == 200,
              let body = String(bytes: response.data, encoding: .utf8) else { return nil }
        return fileMatches(body, token: token) ? "well_known_file" : nil
    }

    struct ProbeKey: StorageKey {
        typealias Value = DomainProbe
    }

    /// The probe in use: live by default; tests install their own.
    static func domainProbe(for app: Application) -> DomainProbe {
        app.storage[ProbeKey.self] ?? liveDomainProbe
    }
}
