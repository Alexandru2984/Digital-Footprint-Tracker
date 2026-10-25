import Foundation

/// Offline facts about an international number, from libphonenumber's data
/// (`PhoneData`): the country of its calling code, the region its prefix was
/// assigned to, and the carrier its range was first allocated to. No key, no
/// request. Where a number was allocated is not where its owner lives, and a
/// ported number keeps its original carrier here.
enum PhoneLookup {
    struct Info: Equatable {
        let callingCode: String
        let countryCode: String
        let country: String
        let region: String?
        let carrier: String?
    }

    private static let codes = parse(PhoneData.callingCodes)
    private static let regions = parse(PhoneData.regions)
    private static let carriers = parse(PhoneData.carriers)
    private static let canadianProvinces: Set<String> = [
        "Alberta", "British Columbia", "Manitoba", "New Brunswick", "Newfoundland and Labrador", "Nova Scotia",
        "Ontario", "Prince Edward Island", "Quebec", "Saskatchewan", "Northwest Territories", "Nunavut", "Yukon",
    ]

    /// `digits`: the number in international form, without `+` or separators.
    static func lookup(_ digits: String) -> Info? {
        guard (7...15).contains(digits.count), digits.allSatisfy(\.isASCII), digits.allSatisfy(\.isNumber),
              let callingCode = (1...3).map({ String(digits.prefix($0)) }).first(where: { codes[$0] != nil }),
              let territories = codes[callingCode]?.split(separator: ","), var iso = territories.first.map(String.init)
        else { return nil }
        let region = longestPrefix(of: digits, in: regions)
        // One code, many countries: North America's states and provinces say which.
        if callingCode == "1", let region {
            if canadianProvinces.contains(region) { iso = "CA" }
            else if let match = territories.map(String.init).first(where: { name(of: $0) == region }) { iso = match }
        }
        return Info(callingCode: callingCode, countryCode: iso, country: name(of: iso) ?? iso,
                    region: region == name(of: iso) ? nil : region,
                    carrier: longestPrefix(of: digits, in: carriers))
    }

    private static func name(of iso: String) -> String? {
        Locale(identifier: "en_US").localizedString(forRegionCode: iso)
    }

    private static func longestPrefix(of digits: String, in table: [String: String]) -> String? {
        for length in stride(from: min(digits.count, 10), through: 1, by: -1) {
            if let value = table[String(digits.prefix(length))] { return value }
        }
        return nil
    }

    private static func parse(_ block: String) -> [String: String] {
        var table: [String: String] = [:]
        for line in block.split(separator: "\n") {
            guard let bar = line.firstIndex(of: "|") else { continue }
            table[String(line[..<bar])] = String(line[line.index(after: bar)...])
        }
        return table
    }
}
