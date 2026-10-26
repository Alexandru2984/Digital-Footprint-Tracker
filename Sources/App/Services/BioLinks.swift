import Foundation

/// What a profile's free text says about its owner's other identities: a
/// contact address ("business: ana@x.dev"), a link to another account
/// (`github.com/ana`, `https://twitch.tv/ana`), a Mastodon handle with its
/// instance. Kept apart from the profile's structured links (`linked`), which
/// can be verified: text anyone typed is only declared.
enum BioLinks {
    /// The `linked`-style value for `text`, nil when it names nothing.
    /// `dropping`: platforms whose links in this text name others as often as
    /// the owner (a README links other people's repositories).
    static func linked(in text: String?, excluding own: String? = nil, limit: Int = 2_000,
                       dropping: Set<String> = []) -> String? {
        guard let text, !text.isEmpty else { return nil }
        let sample = String(text.prefix(limit))
        var pairs: [(String, String?)] = []
        // Mastodon handles first, so their `@user@host` is not read as an address.
        var rest = sample
        for match in sample.matches(of: #/(?:^|[^\w@])@([A-Za-z0-9_]{1,30})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/#) {
            pairs.append(("mastodon", "\(match.output.1)@\(match.output.2.lowercased())"))
            rest = rest.replacingOccurrences(of: String(match.output.0), with: " ")
        }
        for match in rest.matches(of: #/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/#) {
            if let email = EmailAddress.normalize(String(match.output)) { pairs.append(("email", email)) }
        }
        for match in rest.matches(of: #/(?:https?://)?(?:www\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/[^\s<>"'),]+/#) {
            // A sentence's own punctuation is not part of the link.
            let raw = String(match.output).trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?"))
            guard !raw.hasPrefix("http://") else { continue }
            let url = raw.hasPrefix("https://") ? raw : "https://\(raw)"
            if let (platform, value) = IdentityLinks.account(at: url), platform != "web" { pairs.append((platform, value)) }
        }
        let ownKey = own?.lowercased()
        let kept = pairs.filter { !dropping.contains($0.0) && "\($0.0):\($0.1 ?? "")".lowercased() != ownKey }.prefix(10)
        return IdentityLinks.linked(Array(kept))
    }

    /// Two `linked` values as one, without repeats.
    static func merged(_ values: String?...) -> String? {
        var seen: Set<String> = []
        let entries = values.compactMap { $0 }.flatMap { $0.split(separator: ",").map(String.init) }
            .filter { seen.insert($0.lowercased()).inserted }
        return entries.isEmpty ? nil : entries.prefix(16).joined(separator: ",")
    }
}
