import Foundation

/// A subdomain whose CNAME points at a third-party service where nothing is
/// claimed any more: whoever claims that name there serves content on the
/// subdomain, with its cookies and its reputation. Two signals, after the
/// community list at github.com/EdOverflow/can-i-take-over-xyz:
/// - the CNAME's target does not exist (NXDOMAIN): dangling, whatever the
///   service;
/// - the service answers with its "nothing here" page, for services that let
///   anyone claim a name and say so on that page.
enum SubdomainTakeover {
    struct Service: Equatable {
        let name: String
        let suffixes: [String]
        /// Text of the service's page for an unclaimed name; nil when only a
        /// missing target tells.
        let unclaimed: String?
    }

    static let services: [Service] = [
        Service(name: "GitHub Pages", suffixes: ["github.io"], unclaimed: "There isn't a GitHub Pages site here"),
        Service(name: "Amazon S3", suffixes: ["s3.amazonaws.com", "amazonaws.com"], unclaimed: "NoSuchBucket"),
        Service(name: "Heroku", suffixes: ["herokuapp.com", "herokudns.com"], unclaimed: "No such app"),
        Service(name: "Azure", suffixes: ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
                                          "blob.core.windows.net", "azureedge.net", "azure-api.net"], unclaimed: nil),
        Service(name: "AWS Elastic Beanstalk", suffixes: ["elasticbeanstalk.com"], unclaimed: nil),
        Service(name: "Bitbucket", suffixes: ["bitbucket.io"], unclaimed: "Repository not found"),
        Service(name: "Pantheon", suffixes: ["pantheonsite.io"],
                unclaimed: "The gods are wise, but do not know of the site which you seek"),
        Service(name: "Surge.sh", suffixes: ["surge.sh"], unclaimed: "project not found"),
        Service(name: "Tumblr", suffixes: ["domains.tumblr.com"],
                unclaimed: "Whatever you were looking for doesn't currently exist at this address"),
        Service(name: "Help Scout", suffixes: ["helpscoutdocs.com"], unclaimed: "No settings were found for this company"),
        Service(name: "ReadMe", suffixes: ["readme.io"], unclaimed: "Project doesnt exist... yet!"),
        Service(name: "Shopify", suffixes: ["myshopify.com"], unclaimed: "Sorry, this shop is currently unavailable"),
        Service(name: "Ngrok", suffixes: ["ngrok.io"], unclaimed: "Tunnel "),
        Service(name: "Agile CRM", suffixes: ["agilecrm.com"], unclaimed: "Sorry, this page is no longer available"),
    ]

    static func service(for cname: String) -> Service? {
        let host = cname.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return services.first { $0.suffixes.contains { host == $0 || host.hasSuffix(".\($0)") } }
    }

    /// The finding for `host` → `cname`, if either signal fires. `targetExists`
    /// is the CNAME target's DNS answer (nil: unknown); `body` the page the
    /// subdomain serves, when it was fetched.
    static func evaluate(host: String, domain: String, cname: String, targetExists: Bool?, body: String?) -> PluginResult? {
        let target = cname.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        // A target inside the domain itself is the owner's own record.
        guard target != domain, !target.hasSuffix(".\(domain)") else { return nil }
        let service = service(for: target)
        let why: String
        if targetExists == false {
            why = "its CNAME target \(target) does not exist"
        } else if let service, let marker = service.unclaimed, let body, body.contains(marker) {
            why = "\(service.name) answers that nothing is claimed at \(target)"
        } else {
            return nil
        }
        let label = service.map { " (\($0.name))" } ?? ""
        return PluginResult(
            source: "AttackSurface", type: "subdomain_takeover", confidenceScore: service == nil ? 0.7 : 0.9,
            rawData: "\(host) can likely be taken over\(label): \(why). Whoever claims it serves content on \(host).",
            metadata: ["subdomain": host, "domain": domain, "cname": target, "service": service?.name ?? "unknown"])
    }
}
