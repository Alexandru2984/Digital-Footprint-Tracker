import Vapor
import Foundation

/// Email intelligence: deliverability (MX lookup via DoH), mailbox-provider
/// fingerprinting from the MX hosts, and disposable/temporary-provider detection.
/// Turns a bare address into context an analyst needs — is it real, who hosts it,
/// is it a throwaway.
struct EmailIntelPlugin: FootprintPlugin {
    let name = "EmailIntel"
    let description = "Email deliverability, mailbox provider, disposable detection"
    let cacheTTL: TimeInterval = 86_400 // MX + disposable status are very stable

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        guard input.contains("@") else { return [] }
        let email = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let at = email.firstIndex(of: "@") else { return [] }
        let domain = String(email[email.index(after: at)...])
        guard domain.contains(".") else { return [] }

        var results: [PluginResult] = []

        if Self.isDisposable(domain) {
            results.append(PluginResult(
                source: name,
                type: "disposable_email",
                confidenceScore: 0.6,
                rawData: "Disposable / temporary email provider: \(domain)",
                metadata: ["email": email, "domain": domain, "disposable": "true"]
            ))
        }

        let mxHosts = await DoHResolver.resolve(domain, type: "MX").map { DoHResolver.mxHost($0) }.filter { !$0.isEmpty }
        if mxHosts.isEmpty {
            results.append(PluginResult(
                source: name,
                type: "email_intel",
                confidenceScore: 0.5,
                rawData: "No MX records for \(domain) — address is likely undeliverable.",
                metadata: ["email": email, "domain": domain, "deliverable": "false"]
            ))
        } else {
            let provider = Self.mxProvider(mxHosts)
            var meta: [String: String] = ["email": email, "domain": domain, "deliverable": "true"]
            if let provider { meta["mxProvider"] = provider }
            var raw = "Deliverable (MX: \(mxHosts.prefix(3).joined(separator: ", ")))"
            if let provider { raw += " — provider: \(provider)" }
            results.append(PluginResult(
                source: name,
                type: "email_intel",
                confidenceScore: 0.4,
                rawData: raw,
                metadata: meta
            ))
        }

        return results
    }

    /// Identifies the mailbox provider from MX hostnames. Pure + internal for tests.
    static func mxProvider(_ hosts: [String]) -> String? {
        let joined = hosts.joined(separator: " ").lowercased()
        if joined.contains("google") || joined.contains("googlemail")        { return "Google (Gmail / Workspace)" }
        if joined.contains("outlook") || joined.contains("office365") || joined.contains("microsoft") { return "Microsoft (Outlook / 365)" }
        if joined.contains("protonmail") || joined.contains("proton.me")      { return "Proton Mail" }
        if joined.contains("zoho")                                            { return "Zoho" }
        if joined.contains("yahoodns") || joined.contains("yahoo")            { return "Yahoo" }
        if joined.contains("icloud") || joined.contains("apple")              { return "Apple iCloud" }
        if joined.contains("yandex")                                          { return "Yandex" }
        if joined.contains("mailgun") || joined.contains("sendgrid") || joined.contains("amazonses") { return "Transactional ESP" }
        return nil
    }

    /// Curated set of well-known disposable / temporary email domains. Pure for tests.
    static func isDisposable(_ domain: String) -> Bool {
        disposableDomains.contains(domain.lowercased())
    }

    private static let disposableDomains: Set<String> = [
        "mailinator.com", "guerrillamail.com", "guerrillamail.net", "10minutemail.com",
        "temp-mail.org", "tempmail.com", "tempmailo.com", "throwawaymail.com",
        "yopmail.com", "getnada.com", "trashmail.com", "trashmail.de", "sharklasers.com",
        "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com", "mintemail.com",
        "moakt.com", "mohmal.com", "emailondeck.com", "tempinbox.com", "mailcatch.com",
        "spam4.me", "spamgourmet.com", "mytemp.email", "tmail.ws", "burnermail.io",
        "33mail.com", "anonbox.net", "discard.email", "mailsac.com", "inboxkitten.com",
        "tempr.email", "cs.email", "email-temp.com", "luxusmail.org", "1secmail.com",
        "1secmail.net", "1secmail.org", "wegwerfmail.de", "tempemail.co", "gettempmail.com",
        "fakemailgenerator.com", "guerrillamailblock.com", "pokemail.net", "spambog.com",
        "tempmail.plus", "minuteinbox.com", "mailpoof.com", "vomoto.com", "deadaddress.com",
        "harakirimail.com", "incognitomail.com", "jetable.org", "kasmail.com", "nowmymail.com",
        "rcpt.at", "selfdestructingmail.com", "spamfree24.org", "tempomail.fr", "trbvm.com"
    ]
}
