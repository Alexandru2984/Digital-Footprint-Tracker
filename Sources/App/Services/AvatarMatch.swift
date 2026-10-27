import Vapor
import Foundation

/// The same profile picture on two platforms: people reuse their photo far
/// more than strangers share one, so two accounts showing it are likely one
/// person's. Pictures are compared by a perceptual hash (64-bit difference
/// hash), which survives each platform's resizing and re-encoding. Decoding
/// runs in the report runtime's Python (Pillow), in a bounded child process,
/// limited to the four web image formats.
enum AvatarMatch {
    struct Avatar: Equatable {
        /// The account's node in the identity graph: `platform: name`, or an
        /// address for an account known only by it (Gravatar).
        let node: String
        let platform: String
        let url: String

        var isAddress: Bool { !node.contains(": ") }
        /// The node as a `linked` entry.
        var linkedForm: String { isAddress ? "email:\(node)" : node.replacingOccurrences(of: ": ", with: ":") }
    }

    struct Fingerprint: Equatable {
        let hash: UInt64
        /// Standard deviation of the grey levels: a flat placeholder (one
        /// colour, a letter on a plain field) has little and proves nothing.
        let spread: Double
        /// Distinct colours, nil past 256: a generated avatar (GitHub's
        /// identicons, two colours on a 5×5 grid) is drawn from a few, and
        /// different ones share the grid's shape in grey.
        var colors: Int? = nil
        /// Mean red, green and blue: the grey hash cannot tell colours apart.
        var mean: [Double] = []

        var isGenerated: Bool { colors.map { $0 <= maximumGeneratedColors } ?? false }

        func colourDistance(to other: Fingerprint) -> Double {
            guard mean.count == 3, other.mean.count == 3 else { return 0 }
            return zip(mean, other.mean).map { ($0 - $1) * ($0 - $1) }.reduce(0, +).squareRoot()
        }
    }

    static let maximumAvatars = 12
    static let maximumBytes = 1_024 * 1_024
    /// Bits of 64 that may differ: platforms resize and recompress.
    static let maximumDistance = 6
    static let minimumSpread = 20.0
    static let maximumGeneratedColors = 4
    /// Of 441 (black to white): recompression moves the mean colour little.
    static let maximumColourDistance = 30.0

    /// URLs of pictures every account without one gets.
    private static let placeholderMarkers = ["missing", "default", "placeholder", "no_avatar", "no-avatar", "no-title", "blank", "anonymous"]

    /// The accounts in `results` that show a picture, one per account.
    static func avatars(in results: [PluginResult]) -> [Avatar] {
        var seen: Set<String> = []
        var found: [Avatar] = []
        for result in results {
            let meta = result.metadata ?? [:]
            guard let raw = meta["avatar"]?.trimmingCharacters(in: .whitespaces), raw.hasPrefix("https://"),
                  raw.count <= 1_000, let platform = meta["platform"],
                  !placeholderMarkers.contains(where: { raw.lowercased().contains($0) }),
                  let node = IdentityLinks.node(for: meta, from: "") else { continue }
            guard seen.insert(node).inserted else { continue }
            found.append(Avatar(node: node, platform: IdentityLinks.canonicalPlatform(platform), url: raw))
            if found.count == maximumAvatars { break }
        }
        return found
    }

    /// Pairs on different platforms whose pictures match.
    static func matches(_ avatars: [Avatar], fingerprints: [String: Fingerprint]) -> [(Avatar, Avatar, Int)] {
        var pairs: [(Avatar, Avatar, Int)] = []
        for (index, first) in avatars.enumerated() {
            guard let a = fingerprints[first.node], a.spread >= minimumSpread, !a.isGenerated else { continue }
            for second in avatars[(index + 1)...] where second.platform != first.platform {
                guard let b = fingerprints[second.node], b.spread >= minimumSpread, !b.isGenerated else { continue }
                let distance = (a.hash ^ b.hash).nonzeroBitCount
                if distance <= maximumDistance, a.colourDistance(to: b) <= maximumColourDistance {
                    pairs.append((first, second, distance))
                }
            }
        }
        return pairs
    }

    static func result(for pair: (Avatar, Avatar, Int)) -> PluginResult {
        // An account named by an address is the linked end: the finding's own
        // node must be an account, whoever the scan was about.
        let (first, second) = pair.0.isAddress ? (pair.1, pair.0) : (pair.0, pair.1)
        let distance = pair.2
        let how = distance == 0 ? "identical" : "\(distance) of 64 bits differ"
        let parts = first.node.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        return PluginResult(
            source: "AvatarMatch", type: "avatar_match", confidenceScore: 0.8,
            rawData: "\(first.node) and \(second.node) show the same profile picture (\(how))",
            metadata: ["platform": parts.first ?? first.platform, "username": parts.last ?? "",
                       "linked": second.linkedForm, "linkKind": "observed",
                       "linkReason": "the same profile picture (\(how))"])
    }

    /// Fetches the pictures, fingerprints them and returns a finding per match.
    static func run(on results: [PluginResult], app: Application) async -> [PluginResult] {
        let avatars = avatars(in: results)
        guard Set(avatars.map(\.platform)).count >= 2 else { return [] }
        let images = await withTaskGroup(of: (String, Data)?.self) { group in
            for avatar in avatars {
                group.addTask {
                    guard let url = URL(string: avatar.url),
                          let response = await PluginHTTP.request(
                            url, headers: ["Accept": "image/png,image/jpeg,image/gif,image/webp"], timeout: 8, maxRetries: 0,
                            bodyMode: .complete(maxBytes: maximumBytes), on: app),
                          response.status == 200, isImage(response.data) else { return nil }
                    return (avatar.node, response.data)
                }
            }
            var collected: [String: Data] = [:]
            for await item in group { if let (node, data) = item { collected[node] = data } }
            return collected
        }
        guard images.count >= 2 else { return [] }
        let fingerprints = await fingerprint(images, app: app)
        return matches(avatars, fingerprints: fingerprints).map(result(for:))
    }

    /// PNG, JPEG, GIF or WEBP, by their first bytes.
    static func isImage(_ data: Data) -> Bool {
        let head = [UInt8](data.prefix(12))
        guard head.count == 12 else { return false }
        return head.starts(with: [0x89, 0x50, 0x4E, 0x47]) || head.starts(with: [0xFF, 0xD8, 0xFF])
            || head.starts(with: Array("GIF8".utf8))
            || (head.starts(with: Array("RIFF".utf8)) && Array(head[8..<12]) == Array("WEBP".utf8))
    }

    static func parse(_ output: Data) -> [String: Fingerprint] {
        guard let json = try? JSONSerialization.jsonObject(with: output) as? [String: [String: Any]] else { return [:] }
        return json.compactMapValues { entry in
            guard let hex = entry["hash"] as? String, hex.count == 16, let hash = UInt64(hex, radix: 16),
                  let spread = (entry["spread"] as? NSNumber)?.doubleValue else { return nil }
            let mean = (entry["mean"] as? [NSNumber] ?? []).map(\.doubleValue)
            return Fingerprint(hash: hash, spread: spread, colors: (entry["colors"] as? NSNumber)?.intValue,
                               mean: mean.count == 3 ? mean : [])
        }
    }

    static func fingerprint(_ images: [String: Data], app: Application) async -> [String: Fingerprint] {
        guard let python = Environment.get("REPORT_PYTHON_PATH"),
              let stdin = try? JSONSerialization.data(withJSONObject: images.mapValues { $0.base64EncodedString() })
        else { return [:] }
        let environment = ["PATH": "/usr/bin:/usr/local/bin", "PYTHONNOUSERSITE": "1",
                           "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"]
        guard let execution = try? await BoundedProcess.run(
            executable: python, arguments: ["-I", "-c", script], environment: environment,
            stdin: stdin, timeout: 20, maxOutputBytes: 64 * 1_024
        ), execution.succeeded, !execution.outputExceeded else {
            app.logger.warning("AvatarMatch: fingerprinting unavailable")
            return [:]
        }
        return parse(execution.stdout)
    }

    /// Reads {key: base64 image} on stdin, prints {key: {hash, spread}}. A
    /// picture that does not decode is left out.
    static let script = #"""
import base64, io, json, sys, warnings
from PIL import Image
# A small file can declare a vast canvas: past 4 megapixels it is refused.
Image.MAX_IMAGE_PIXELS = 4_000_000
warnings.simplefilter("error", Image.DecompressionBombWarning)
out = {}
for key, encoded in json.load(sys.stdin).items():
    try:
        image = Image.open(io.BytesIO(base64.b64decode(encoded)), formats=["PNG", "JPEG", "GIF", "WEBP"])
        image.seek(0)
        image = image.convert("RGBA")
        flat = Image.new("RGBA", image.size, (255, 255, 255, 255))
        flat.alpha_composite(image)
        grey = flat.convert("L")
        values = lambda picture: list(getattr(picture, "get_flattened_data", picture.getdata)())
        pixels = values(grey.resize((9, 8), Image.Resampling.LANCZOS))
        bits = 0
        for row in range(8):
            for column in range(8):
                bits = (bits << 1) | (1 if pixels[row * 9 + column] > pixels[row * 9 + column + 1] else 0)
        sample = values(grey.resize((32, 32)))
        mean = sum(sample) / len(sample)
        spread = (sum((value - mean) ** 2 for value in sample) / len(sample)) ** 0.5
        rgb = flat.convert("RGB")
        colours = rgb.resize((64, 64), Image.Resampling.NEAREST).getcolors(maxcolors=256)
        tiny = values(rgb.resize((1, 1), Image.Resampling.BOX))[0]
        out[key] = {"hash": format(bits, "016x"), "spread": round(spread, 1),
                    "colors": len(colours) if colours is not None else None,
                    "mean": [round(channel, 1) for channel in tiny]}
    except Exception:
        pass
print(json.dumps(out))
"""#
}
