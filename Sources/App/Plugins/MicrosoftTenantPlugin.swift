import Vapor
import Foundation

/// The Microsoft 365 (Entra ID) tenant a domain belongs to, from the answers
/// Microsoft gives any sign-in page (no key required): the organisation's
/// name, the tenant ID, the identity provider a federated domain signs in
/// through, and every other domain in the tenant. A domain joins a tenant only
/// once its owner proves control of its DNS, so the tenant's domains have one
/// owner: an old name, a sister brand, an acquisition.
///
/// - GET https://login.microsoftonline.com/getuserrealm.srf?login=nobody@{domain}&json=1
///   → `NameSpaceType` (Managed | Federated | Unknown), `FederationBrandName`, `AuthURL`
/// - GET https://login.microsoftonline.com/{domain}/.well-known/openid-configuration
///   → `issuer` (with the tenant ID), `tenant_region_scope`
/// - POST https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc
///   (GetFederationInformation) → the tenant's domains
struct MicrosoftTenantPlugin: FootprintPlugin {
    let name = "MicrosoftTenant"
    let description = "Microsoft 365 tenant: the organisation's name, its identity provider and the other domains it owns"
    let accepts: Set<TargetShape> = [.domain]
    let cacheTTL: TimeInterval = 86_400

    struct Realm: Equatable {
        let namespace: String
        let brand: String?
        let federation: String?
    }

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        let domain = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard Self.isDomain(domain), !TargetDeriver.isMailProvider(domain) else { return [] }
        var components = URLComponents(string: "https://login.microsoftonline.com/getuserrealm.srf")
        components?.queryItems = [URLQueryItem(name: "login", value: "nobody@\(domain)"), URLQueryItem(name: "json", value: "1")]
        guard let realmURL = components?.url,
              let response = await PluginHTTP.request(realmURL, headers: ["Accept": "application/json"], timeout: 10,
                                                      bodyMode: .complete(maxBytes: 64 * 1_024), on: app),
              response.status == 200, let realm = Self.realm(response.data),
              let configurationURL = URL(string: "https://login.microsoftonline.com/\(domain)/.well-known/openid-configuration"),
              let autodiscoverURL = URL(string: "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc")
        else { return [] }

        async let configuration = PluginHTTP.request(
            configurationURL, headers: ["Accept": "application/json"], timeout: 10,
            bodyMode: .complete(maxBytes: 64 * 1_024), on: app)
        async let federation = PluginHTTP.request(
            autodiscoverURL, method: .POST,
            headers: ["Content-Type": "text/xml; charset=utf-8", "User-Agent": "AutodiscoverClient",
                      "SOAPAction": #""http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation""#],
            body: Data(Self.federationRequest(domain).utf8), timeout: 15, bodyMode: .complete(maxBytes: 512 * 1_024), on: app)
        let tenant = await configuration.flatMap { $0.status == 200 ? Self.tenant($0.data) : nil }
        let domains = await federation.flatMap { response in
            response.status == 200 ? String(bytes: response.data, encoding: .utf8).map(Self.domains) : nil
        } ?? []
        return Self.evaluate(domain: domain, realm: realm, tenantID: tenant?.id, region: tenant?.region, domains: domains)
            .map { [$0] } ?? []
    }

    static func isDomain(_ value: String) -> Bool {
        value.count <= 253 && value.range(of: #"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"#, options: .regularExpression) != nil
    }

    /// The realm, or nil for a domain no tenant claims.
    static func realm(_ body: Data) -> Realm? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let namespace = json["NameSpaceType"] as? String, ["Managed", "Federated"].contains(namespace) else { return nil }
        let brand = (json["FederationBrandName"] as? String)?.trimmingCharacters(in: .whitespaces)
        let federation = (json["AuthURL"] as? String).flatMap { URL(string: $0)?.host?.lowercased() }
        return Realm(namespace: namespace, brand: brand.flatMap { $0.isEmpty || $0.count > 120 ? nil : $0 },
                     federation: namespace == "Federated" ? federation : nil)
    }

    static func tenant(_ body: Data) -> (id: String, region: String?)? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let issuer = json["issuer"] as? String,
              let match = issuer.firstMatch(of: #/^https://sts\.windows\.net/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/$/#)
        else { return nil }
        let region = (json["tenant_region_scope"] as? String).flatMap { $0.count <= 8 ? $0 : nil }
        return (String(match.output.1), region)
    }

    static func federationRequest(_ domain: String) -> String {
        """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
        <soap:Header>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
        </soap:Header>
        <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
        <Request><Domain>\(domain)</Domain></Request>
        </GetFederationInformationRequestMessage>
        </soap:Body>
        </soap:Envelope>
        """
    }

    static func domains(_ xml: String) -> [String] {
        var found: [String] = []
        for match in xml.matches(of: #/<Domain>([^<]{1,253})</Domain>/#) {
            let host = match.output.1.trimmingCharacters(in: .whitespaces).lowercased()
            if isDomain(host), !found.contains(host) { found.append(host) }
            if found.count == 1_000 { break }
        }
        return found
    }

    static func evaluate(domain: String, realm: Realm, tenantID: String?, region: String?, domains: [String]) -> PluginResult? {
        let tenantName = domains.first { $0.hasSuffix(".onmicrosoft.com") && !$0.hasSuffix(".mail.onmicrosoft.com") }
            .map { String($0.dropLast(".onmicrosoft.com".count)) }
        // The others, each by its highest name in the tenant: `pub.ro` stands
        // for `cs.pub.ro`; the scanned domain's own subdomains are its own.
        let foreign = Set(domains.filter {
            $0 != domain && !$0.hasSuffix(".\(domain)") && !domain.hasSuffix(".\($0)") && !$0.hasSuffix(".onmicrosoft.com")
        })
        let others = domains.filter { host in
            foreign.contains(host) && !foreign.contains { host.hasSuffix(".\($0)") }
        }
        var parts = ["\(domain) is in a Microsoft 365 tenant (\(realm.namespace.lowercased()))"]
        var meta = ["platform": "web", "account": domain, "domain": domain, "namespace": realm.namespace,
                    "matchKind": "verified", "matchReason": "the domain itself"]
        // The brand is the organisation's name unless it just repeats a domain.
        if let brand = realm.brand, !domains.contains(brand.lowercased()), brand.lowercased() != domain {
            parts.append("Organization: \(brand)")
            meta["org"] = brand
        }
        if let tenantID {
            parts.append("Tenant ID: \(tenantID)" + (region.map { " (\($0))" } ?? ""))
            meta["tenantID"] = tenantID
        }
        if let region { meta["region"] = region }
        if let tenantName {
            parts.append("Tenant name: \(tenantName)")
            meta["tenantName"] = tenantName
        }
        if let federation = realm.federation {
            parts.append("Signs in through \(federation)")
            meta["federation"] = federation
        }
        if !domains.isEmpty { meta["domainCount"] = String(domains.count) }
        if !others.isEmpty {
            meta["domains"] = others.prefix(40).joined(separator: ",")
            // A tenant of a few domains is one owner's handful of sites; one of
            // hundreds is a conglomerate's, listed but not followed one by one.
            if others.count <= 20 {
                meta["linked"] = others.prefix(10).map { "web:\($0)" }.joined(separator: ",")
                meta["linkKind"] = "verified"
                meta["linkReason"] = "in the same Microsoft 365 tenant, which verified each domain's DNS"
            }
            parts.append("Other domains in the tenant (\(others.count)): " + others.prefix(15).joined(separator: ", ")
                         + (others.count > 15 ? ", …" : ""))
        }
        return PluginResult(source: "MicrosoftTenant", type: "microsoft_tenant", confidenceScore: 0.9,
                            rawData: parts.joined(separator: " | "), metadata: meta)
    }
}
