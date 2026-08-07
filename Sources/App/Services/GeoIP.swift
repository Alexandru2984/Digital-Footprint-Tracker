import Foundation
import Vapor
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Offline geolocation from a local MaxMind DB (GeoLite2-City `.mmdb`).
///
/// Privacy-first replacement for the old `/api/geolocate` proxy, which forwarded
/// the IP addresses surfaced by a scan to `http://ip-api.com` in cleartext — a
/// third party learned exactly which hosts a user was investigating, and any
/// on-path observer could read it. This reader answers the same query with a
/// file on disk: nothing leaves the box.
///
/// Pure Swift, no third-party dependency. Implements just enough of the MaxMind
/// DB binary format (search tree + typed data section) to resolve a city record.
/// The database is memory-mapped once at startup and shared read-only; lookups
/// are lock-free reads.
///
/// Format reference: https://maxmind.github.io/MaxMind-DB/
final class GeoIP: @unchecked Sendable {

    struct Location: Content {
        let query: String
        let status: String
        var country: String?
        var countryCode: String?
        var regionName: String?
        var city: String?
        var lat: Double?
        var lon: Double?
        /// Autonomous System number + operator (from the offline GeoLite2-ASN DB).
        /// `isp` populates the "ISP" line the map popup already renders.
        var asn: Int?
        var isp: String?
    }

    /// Optional sibling reader for the ASN database, held by the City instance.
    private var asnDB: GeoIP?

    private let data: [UInt8]
    private let nodeCount: UInt32
    private let recordSize: UInt32          // 24, 28, or 32 bits
    private let nodeSizeBytes: Int          // recordSize * 2 / 8
    private let searchTreeSize: Int         // nodeCount * nodeSizeBytes
    private let ipVersion: Int              // 4 or 6

    // MARK: - Loading

    /// Attempt to open a `.mmdb` at one of the candidate paths (env override
    /// first). Returns nil if none is present/parseable so the caller can degrade
    /// gracefully rather than crash.
    static func open(app: Application) -> GeoIP? {
        var candidates: [String] = []
        if let p = Environment.get("GEOIP_DB_PATH"), !p.isEmpty { candidates.append(p) }
        candidates.append(contentsOf: [
            "/home/micu/umami/geo/GeoLite2-City.mmdb",
            "/var/lib/crowdsec/data/GeoLite2-City.mmdb",
            app.directory.workingDirectory + "GeoLite2-City.mmdb"
        ])
        for path in candidates {
            if FileManager.default.fileExists(atPath: path), let db = GeoIP(path: path) {
                app.logger.notice("GeoIP: loaded offline database from \(path)")
                db.asnDB = openASN(app: app)
                return db
            }
        }
        app.logger.warning("GeoIP: no local GeoLite2-City.mmdb found — /api/geolocate will return status=fail")
        return nil
    }

    /// Load the companion ASN database (autonomous system number + operator).
    /// Optional — geolocation still works without it, just with no ISP line.
    private static func openASN(app: Application) -> GeoIP? {
        var candidates: [String] = []
        if let p = Environment.get("GEOIP_ASN_DB_PATH"), !p.isEmpty { candidates.append(p) }
        candidates.append(contentsOf: [
            "/home/micu/umami/geo/GeoLite2-ASN.mmdb",
            "/var/lib/crowdsec/data/GeoLite2-ASN.mmdb",
            app.directory.workingDirectory + "GeoLite2-ASN.mmdb"
        ])
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            if let db = GeoIP(path: path) {
                app.logger.notice("GeoIP: loaded offline ASN database from \(path)")
                return db
            }
        }
        return nil
    }

    init?(path: String) {
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else {
            return nil
        }
        let bytes = [UInt8](fileData)
        // Metadata begins after the last occurrence of this marker. The three
        // leading bytes are raw (0xAB 0xCD 0xEF) — they must NOT be built from a
        // Swift string, whose UTF-8 encoding would turn each into two bytes.
        let marker: [UInt8] = [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
        guard let metaStart = GeoIP.lastIndex(of: marker, in: bytes) else { return nil }
        let metaOffset = metaStart + marker.count

        // Decode the metadata map (data-section encoding, but offsets here are
        // relative to metaOffset, so use a decoder anchored there).
        let metaDecoder = Decoder(data: bytes, base: metaOffset)
        guard case let .map(meta)? = metaDecoder.decode(at: 0)?.value,
              case let .uint(nc)? = meta["node_count"],
              case let .uint(rs)? = meta["record_size"],
              case let .uint(iv)? = meta["ip_version"] else {
            return nil
        }
        guard rs == 24 || rs == 28 || rs == 32 else { return nil }

        self.data = bytes
        self.nodeCount = UInt32(nc)
        self.recordSize = UInt32(rs)
        self.nodeSizeBytes = Int(rs) * 2 / 8
        self.searchTreeSize = Int(nc) * (Int(rs) * 2 / 8)
        self.ipVersion = Int(iv)
    }

    // MARK: - Lookup

    /// Resolve an IPv4 or IPv6 string to a city record. Returns a `Location` with
    /// `status: "fail"` for private/unroutable/unknown inputs (never throws).
    func lookup(_ ipString: String) -> Location {
        let fail = Location(query: ipString, status: "fail")
        guard let bits = GeoIP.addressBits(ipString, dbIsV6: ipVersion == 6) else { return fail }
        guard let dataOffset = traverse(bits: bits) else { return fail }

        let decoder = Decoder(data: data, base: searchTreeSize + Constants.separator)
        // dataOffset is relative to the data section start.
        guard case let .map(record)? = decoder.decode(at: dataOffset - Constants.separator)?.value else {
            return fail
        }

        var loc = Location(query: ipString, status: "success")
        if case let .map(country)? = record["country"] {
            if case let .string(code)? = country["iso_code"] { loc.countryCode = code }
            if case let .map(names)? = country["names"], case let .string(en)? = names["en"] { loc.country = en }
        }
        if case let .map(city)? = record["city"],
           case let .map(names)? = city["names"], case let .string(en)? = names["en"] {
            loc.city = en
        }
        if case let .array(subs)? = record["subdivisions"], let first = subs.first,
           case let .map(sub) = first, case let .map(names)? = sub["names"],
           case let .string(en)? = names["en"] {
            loc.regionName = en
        }
        if case let .map(location)? = record["location"] {
            if case let .double(lat)? = location["latitude"] { loc.lat = lat }
            if case let .double(lon)? = location["longitude"] { loc.lon = lon }
        }
        // The map UI plots `[lat, lon]`; a record without coordinates (e.g. an
        // anycast IP that only carries a registered_country) must not surface as
        // a placeable point. Report it as fail so the client filter drops it.
        guard loc.lat != nil, loc.lon != nil else {
            return Location(query: ipString, status: "fail")
        }
        // Enrich a plotted point with its network operator from the ASN DB.
        if let asnDB = asnDB {
            let a = asnDB.lookupASN(ipString)
            loc.asn = a.number
            loc.isp = a.org
        }
        return loc
    }

    /// Look up an IP's Autonomous System in the GeoLite2-ASN database. Returns the
    /// AS number and the operator name (e.g. 13335 / "Cloudflare, Inc.").
    func lookupASN(_ ipString: String) -> (number: Int?, org: String?) {
        guard let bits = GeoIP.addressBits(ipString, dbIsV6: ipVersion == 6),
              let dataOffset = traverse(bits: bits) else { return (nil, nil) }
        let decoder = Decoder(data: data, base: searchTreeSize + Constants.separator)
        guard case let .map(record)? = decoder.decode(at: dataOffset - Constants.separator)?.value else {
            return (nil, nil)
        }
        var number: Int?
        var org: String?
        if case let .uint(n)? = record["autonomous_system_number"] { number = Int(n) }
        if case let .string(o)? = record["autonomous_system_organization"] { org = o }
        return (number, org)
    }

    /// Walk the binary search tree bit by bit; return the data-section offset of
    /// the matched record, or nil if the path terminates in the empty record.
    private func traverse(bits: [Bool]) -> Int? {
        var node = 0
        for bit in bits {
            if node >= Int(nodeCount) { break }
            let record = readRecord(node: node, right: bit)
            if record == nodeCount { return nil }          // empty record → no data
            if record < nodeCount { node = Int(record); continue }
            // record > nodeCount → data pointer.
            return Int(record - nodeCount)
        }
        // Ran out of bits landing exactly on a data record.
        if node > Int(nodeCount) { return node - Int(nodeCount) }
        return nil
    }

    /// Read the left (bit=false) or right (bit=true) record of a tree node.
    private func readRecord(node: Int, right: Bool) -> UInt32 {
        let base = node * nodeSizeBytes
        switch recordSize {
        case 24:
            let o = base + (right ? 3 : 0)
            return (UInt32(data[o]) << 16) | (UInt32(data[o + 1]) << 8) | UInt32(data[o + 2])
        case 28:
            if right {
                return ((UInt32(data[base + 3]) & 0x0F) << 24)
                    | (UInt32(data[base + 4]) << 16) | (UInt32(data[base + 5]) << 8) | UInt32(data[base + 6])
            } else {
                return (((UInt32(data[base + 3]) & 0xF0) >> 4) << 24)
                    | (UInt32(data[base]) << 16) | (UInt32(data[base + 1]) << 8) | UInt32(data[base + 2])
            }
        default: // 32
            let o = base + (right ? 4 : 0)
            return (UInt32(data[o]) << 24) | (UInt32(data[o + 1]) << 16)
                | (UInt32(data[o + 2]) << 8) | UInt32(data[o + 3])
        }
    }

    // MARK: - Address → bit array

    /// Convert an IP string to the bit sequence used to walk the tree. For a v6
    /// database queried with a v4 address, MaxMind looks it up as `::0.0.0.0/96`
    /// — 96 leading zero bits then the 32 v4 bits. Rejects private/loopback IPs
    /// (defense-in-depth; the caller shouldn't be geolocating those anyway).
    static func addressBits(_ s: String, dbIsV6: Bool) -> [Bool]? {
        var v4 = in_addr()
        if s.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let addr = UInt32(bigEndian: v4.s_addr)
            var bits = [Bool]()
            if dbIsV6 { bits.append(contentsOf: Array(repeating: false, count: 96)) }
            for i in stride(from: 31, through: 0, by: -1) { bits.append((addr >> UInt32(i)) & 1 == 1) }
            return bits
        }
        var v6 = in6_addr()
        if s.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            let octets = withUnsafeBytes(of: &v6) { Array($0) }
            var bits = [Bool]()
            for byte in octets { for i in stride(from: 7, through: 0, by: -1) { bits.append((byte >> UInt8(i)) & 1 == 1) } }
            return bits
        }
        return nil
    }

    private static func lastIndex(of pattern: [UInt8], in haystack: [UInt8]) -> Int? {
        guard pattern.count <= haystack.count else { return nil }
        var i = haystack.count - pattern.count
        while i >= 0 {
            if Array(haystack[i..<i + pattern.count]) == pattern { return i }
            i -= 1
        }
        return nil
    }

    private enum Constants { static let separator = 16 }

    // MARK: - Typed data-section decoder

    /// Decodes the MaxMind typed data section into a Swift value tree, resolving
    /// pointers. `base` is the absolute offset the section starts at; all offsets
    /// passed to `decode(at:)` are relative to it.
    private final class Decoder {
        enum Value {
            case map([String: Value]); case array([Value]); case string(String)
            case double(Double); case uint(UInt64); case int(Int64); case bool(Bool)
            case bytes([UInt8]); case float(Float)
        }
        struct Decoded { let value: Value; let next: Int }

        let data: [UInt8]
        let base: Int
        init(data: [UInt8], base: Int) { self.data = data; self.base = base }

        func decode(at offset: Int) -> Decoded? {
            var p = base + offset
            guard p < data.count else { return nil }
            let ctrl = data[p]; p += 1
            var type = Int(ctrl >> 5)
            if type == 0 { // extended type: real type = next byte + 7
                guard p < data.count else { return nil }
                type = Int(data[p]) + 7; p += 1
            }

            // Pointer (type 1) — size bits encode the pointer, not a length.
            if type == 1 {
                let sizeSel = Int((ctrl >> 3) & 0x3)
                let value: Int
                switch sizeSel {
                case 0:
                    value = (Int(ctrl & 0x7) << 8) | Int(data[p]); p += 1
                case 1:
                    // + 2048 applies to the whole assembled pointer, not the last
                    // byte — parenthesise so `|` finishes before `+` (which binds
                    // tighter in Swift).
                    value = ((Int(ctrl & 0x7) << 16) | (Int(data[p]) << 8) | Int(data[p + 1])) + 2048; p += 2
                case 2:
                    value = ((Int(ctrl & 0x7) << 24) | (Int(data[p]) << 16) | (Int(data[p + 1]) << 8) | Int(data[p + 2])) + 526336; p += 3
                default:
                    value = (Int(data[p]) << 24) | (Int(data[p + 1]) << 16) | (Int(data[p + 2]) << 8) | Int(data[p + 3]); p += 4
                }
                // Pointer target is relative to the section base; decode there but
                // report `next` as the position after the pointer itself.
                guard let target = decode(at: value) else { return nil }
                return Decoded(value: target.value, next: p - base)
            }

            // Size for length-prefixed types.
            var size = Int(ctrl & 0x1F)
            if size >= 29 {
                switch size {
                case 29: size = 29 + Int(data[p]); p += 1
                case 30: size = 285 + (Int(data[p]) << 8) + Int(data[p + 1]); p += 2
                default: size = 65821 + (Int(data[p]) << 16) + (Int(data[p + 1]) << 8) + Int(data[p + 2]); p += 3
                }
            }

            let contentStart = p
            switch type {
            case 2: // UTF-8 string
                let str = String(decoding: data[contentStart..<contentStart + size], as: UTF8.self)
                return Decoded(value: .string(str), next: contentStart + size - base)
            case 3: // double (8 bytes, big-endian IEEE754)
                let bits = beUInt(contentStart, 8)
                return Decoded(value: .double(Double(bitPattern: bits)), next: contentStart + 8 - base)
            case 4: // bytes
                return Decoded(value: .bytes(Array(data[contentStart..<contentStart + size])), next: contentStart + size - base)
            case 5, 6, 9, 10: // uint16/32/64/128 (treat 128 as truncated u64)
                return Decoded(value: .uint(beUInt(contentStart, size)), next: contentStart + size - base)
            case 7: // map
                var dict = [String: Value](); var cur = contentStart - base
                for _ in 0..<size {
                    guard let k = decode(at: cur), case let .string(key) = k.value else { return nil }
                    cur = k.next
                    guard let v = decode(at: cur) else { return nil }
                    cur = v.next
                    dict[key] = v.value
                }
                return Decoded(value: .map(dict), next: cur)
            case 8: // int32
                let raw = beUInt(contentStart, size)
                return Decoded(value: .int(Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: raw)))), next: contentStart + size - base)
            case 11: // array
                var arr = [Value](); var cur = contentStart - base
                for _ in 0..<size {
                    guard let v = decode(at: cur) else { return nil }
                    arr.append(v.value); cur = v.next
                }
                return Decoded(value: .array(arr), next: cur)
            case 14: // boolean (size is the value)
                return Decoded(value: .bool(size != 0), next: contentStart - base)
            case 15: // float (4 bytes)
                let bits = UInt32(truncatingIfNeeded: beUInt(contentStart, 4))
                return Decoded(value: .float(Float(bitPattern: bits)), next: contentStart + 4 - base)
            default:
                return Decoded(value: .bool(false), next: contentStart + size - base)
            }
        }

        private func beUInt(_ start: Int, _ n: Int) -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<n where start + i < data.count { v = (v << 8) | UInt64(data[start + i]) }
            return v
        }
    }
}

// MARK: - Application storage

extension Application {
    private struct GeoIPKey: StorageKey { typealias Value = GeoIP }
    /// The process-wide offline GeoIP reader, loaded once at boot (nil if no DB
    /// was found). Read-only after startup, safe to share across requests.
    var geoIP: GeoIP? {
        get { storage[GeoIPKey.self] }
        set { storage[GeoIPKey.self] = newValue }
    }
}
