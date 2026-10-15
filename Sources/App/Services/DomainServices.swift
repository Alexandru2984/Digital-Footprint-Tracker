import Foundation

/// The services a domain's owner uses, read from what those services make
/// them publish: ownership tokens in TXT records, senders allowed by SPF, and
/// the mail servers in MX. A company on Microsoft 365, Atlassian and Stripe
/// says so in its DNS.
enum DomainServices {
    struct Finding: Equatable {
        let service: String
        let evidence: String
    }

    /// TXT prefix (lowercased) → service.
    private static let tokens: [(String, String)] = [
        ("google-site-verification=", "Google"), ("ms=", "Microsoft 365"),
        ("facebook-domain-verification=", "Meta (Facebook)"), ("atlassian-domain-verification=", "Atlassian"),
        ("apple-domain-verification=", "Apple"), ("adobe-idp-site-verification=", "Adobe"),
        ("docusign=", "DocuSign"), ("stripe-verification=", "Stripe"), ("zoom-domain-verification", "Zoom"),
        ("zoom_verify_", "Zoom"), ("slack-domain-verification=", "Slack"), ("dropbox-domain-verification=", "Dropbox"),
        ("hubspot-developer-verification=", "HubSpot"), ("miro-verification=", "Miro"),
        ("onetrust-domain-verification=", "OneTrust"), ("yandex-verification:", "Yandex"),
        ("have-i-been-pwned-verification=", "Have I Been Pwned"), ("openai-domain-verification=", "OpenAI"),
        ("anthropic-domain-verification", "Anthropic"), ("brevo-code:", "Brevo"), ("mandrill_verify.", "Mailchimp"),
        ("cisco-ci-domain-verification=", "Webex"), ("postman-domain-verification=", "Postman"),
        ("globalsign-domain-verification=", "GlobalSign"), ("teamviewer-sso-verification=", "TeamViewer"),
        ("canva-site-verification=", "Canva"), ("figma-domain-verification=", "Figma"),
        ("cursor-domain-verification", "Cursor"), ("knowbe4-site-verification=", "KnowBe4"),
        ("wiz-domain-verification=", "Wiz"), ("twilio-domain-verification=", "Twilio"),
        ("github-verification", "GitHub"), ("gitlab-pages-verification-code=", "GitLab"),
        ("keybase-site-verification=", "Keybase"), ("protonmail-verification=", "Proton Mail"),
    ]

    /// Host fragment in an SPF `include:` or an MX host → service.
    private static let mailHosts: [(String, String)] = [
        ("_spf.google.com", "Google Workspace"), ("google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"), ("protection.outlook.com", "Microsoft 365"),
        ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
        ("zoho.", "Zoho Mail"), ("zendesk.com", "Zendesk"), ("mcsv.net", "Mailchimp"),
        ("mandrillapp.com", "Mailchimp"), ("salesforce.com", "Salesforce"), ("protonmail.ch", "Proton Mail"),
        ("messagingengine.com", "Fastmail"), ("mx.cloudflare.net", "Cloudflare Email Routing"),
        ("improvmx.com", "ImprovMX"), ("mailjet.com", "Mailjet"), ("sparkpostmail.com", "SparkPost"),
        ("postmarkapp.com", "Postmark"), ("hubspotemail.net", "HubSpot"), ("freshdesk.com", "Freshdesk"),
        ("helpscoutemail.com", "Help Scout"), ("mimecast.com", "Mimecast"), ("pphosted.com", "Proofpoint"),
        ("yandex.net", "Yandex"), ("migadu.com", "Migadu"), ("icloud.com", "iCloud Mail"),
    ]

    static func detect(txt: [String], mx: [String]) -> [Finding] {
        var found: [Finding] = []
        func add(_ service: String, _ evidence: String) {
            guard !found.contains(where: { $0.service == service }) else { return }
            found.append(Finding(service: service, evidence: evidence))
        }
        for record in txt.prefix(100) {
            let lower = record.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            if let match = tokens.first(where: { lower.hasPrefix($0.0) }) {
                add(match.1, "TXT verification")
            }
            if lower.hasPrefix("v=spf1") {
                for term in lower.split(separator: " ") where term.hasPrefix("include:") {
                    let host = term.dropFirst("include:".count)
                    if let match = mailHosts.first(where: { host.contains($0.0) }) { add(match.1, "SPF sender") }
                }
            }
        }
        for host in mx.prefix(20) {
            let lower = host.lowercased()
            if let match = mailHosts.first(where: { lower.contains($0.0) }) { add(match.1, "mail server") }
        }
        return found
    }
}
