import Foundation

/// Addresses a domain resolves to when it sits behind a CDN or a shared web
/// host. Thousands of unrelated sites answer on the same address, so what
/// Shodan, VirusTotal or AbuseIPDB say about it describes the provider, not
/// the target: Cloudflare's edge has a dozen open ports and a few "malicious"
/// votes. Such an address is never a pivot.
enum SharedEdge {
    /// Published ranges: Cloudflare (cloudflare.com/ips-v4), Fastly
    /// (api.fastly.com/public-ip-list), GitHub Pages and Vercel. Retrieved
    /// 2026-10-25; they change rarely, and a missed range only means one
    /// noisy pivot.
    private static let ranges: [(base: UInt32, bits: UInt32)] = [
        // Cloudflare
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        // Fastly
        "23.235.32.0/20", "43.249.72.0/22", "90.98.0.0/17", "90.98.128.0/18", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20",
        "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
        // GitHub Pages, Vercel
        "185.199.108.0/22", "76.76.21.0/24",
    ].compactMap { cidr in
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let base = ipv4(String(parts[0])), let bits = UInt32(parts[1]) else { return nil }
        return (base, bits)
    }

    static func contains(_ address: String) -> Bool {
        guard let ip = ipv4(address) else { return false }
        return ranges.contains { range in
            let mask: UInt32 = range.bits == 0 ? 0 : ~0 << (32 - range.bits)
            return ip & mask == range.base & mask
        }
    }

    private static func ipv4(_ s: String) -> UInt32? {
        let octets = s.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var value: UInt32 = 0
        for octet in octets {
            guard octet.count <= 3, let byte = UInt8(octet) else { return nil }
            value = value << 8 | UInt32(byte)
        }
        return value
    }
}
