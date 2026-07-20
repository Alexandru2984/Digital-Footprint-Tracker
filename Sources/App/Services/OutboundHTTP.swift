import AsyncHTTPClient
import Foundation
import Vapor

/// Streaming, size-bounded egress used whenever a destination can be influenced
/// by user or bundled data. AsyncHTTPClient backpressure prevents a peer that
/// ignores `Range` from forcing the full response into process memory.
enum OutboundHTTP {
    enum BodyMode: Sendable {
        /// The complete body is required and must fit within the limit.
        case complete(maxBytes: Int)
        /// Keep only the prefix and stop requesting body chunks at the limit.
        case prefix(maxBytes: Int)
    }

    enum RequestError: Error {
        case invalidURL
        case blockedInternalHost
        case insecureRedirect
        case redirectLimit
        case responseBodyRejected
    }

    struct Response: Sendable {
        let status: Int
        let headers: [String: String]
        let data: Data
        let finalURL: URL
    }

    static func request(
        _ initialURL: URL,
        method: HTTPMethod = .GET,
        headers: [String: String] = [:],
        body: Data? = nil,
        timeout: TimeInterval = 10,
        bodyMode: BodyMode,
        maxRedirects: Int = 0,
        hostPreChecked: Bool = false,
        on app: Application
    ) async throws -> Response {
        guard timeout > 0, maxRedirects >= 0 else { throw RequestError.invalidURL }

        let deadline = Date().addingTimeInterval(timeout)
        var currentURL = try normalized(initialURL)
        var currentMethod = method
        var currentBody = body
        var visited = Set<String>()
        var redirects = 0

        while true {
            guard visited.insert(currentURL.absoluteString).inserted else {
                throw RequestError.redirectLimit
            }
            try await validatePublicDestination(currentURL, skipDNS: hostPreChecked && redirects == 0)

            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw HTTPClientError.deadlineExceeded }

            var request = HTTPClientRequest(url: currentURL.absoluteString)
            request.method = currentMethod
            request.headers.add(name: "User-Agent", value: "Digital-Footprint-Tracker/1.0 (+https://swift.micutu.com)")
            for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
            if let currentBody {
                request.body = .bytes(currentBody)
            }

            let response = try await app.http.client.shared.execute(
                request,
                timeout: .milliseconds(Int64(max(1, remaining * 1_000)))
            )

            if let redirect = redirectTarget(from: response, relativeTo: currentURL) {
                guard redirects < maxRedirects else { throw RequestError.redirectLimit }
                let nextURL = try normalized(redirect)
                if currentURL.scheme?.lowercased() == "https", nextURL.scheme?.lowercased() != "https" {
                    throw RequestError.insecureRedirect
                }

                // Never forward a POST body or caller-provided credentials to a
                // redirected host. Current webhook calls deliberately set zero
                // redirects; this also makes the invariant explicit here.
                guard currentMethod == .GET || currentMethod == .HEAD else {
                    throw RequestError.insecureRedirect
                }
                currentURL = nextURL
                currentBody = nil
                redirects += 1
                continue
            }

            let data: Data
            switch bodyMode {
            case .complete(let maxBytes):
                guard maxBytes >= 0 else { throw RequestError.invalidURL }
                do {
                    let buffer = try await response.body.collect(upTo: maxBytes)
                    data = Data(buffer.readableBytesView)
                } catch {
                    // Do not let a retry loop download an oversized body again.
                    throw RequestError.responseBodyRejected
                }
            case .prefix(let maxBytes):
                guard maxBytes >= 0 else { throw RequestError.invalidURL }
                data = try await collectPrefix(response.body, maxBytes: maxBytes)
            }

            var flattenedHeaders: [String: String] = [:]
            for header in response.headers {
                let name = header.name.lowercased()
                if let existing = flattenedHeaders[name] {
                    flattenedHeaders[name] = existing + ", " + header.value
                } else {
                    flattenedHeaders[name] = header.value
                }
            }
            return Response(
                status: Int(response.status.code),
                headers: flattenedHeaders,
                data: data,
                finalURL: currentURL
            )
        }
    }

    private static func normalized(_ url: URL) throws -> URL {
        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty, host.utf8.count <= 253,
              url.user == nil, url.password == nil,
              url.absoluteString.utf8.count <= 4096 else {
            throw RequestError.invalidURL
        }
        var components = URLComponents(url: url.absoluteURL, resolvingAgainstBaseURL: true)
        components?.fragment = nil
        guard let normalized = components?.url else { throw RequestError.invalidURL }
        return normalized
    }

    private static func validatePublicDestination(_ url: URL, skipDNS: Bool) async throws {
        guard let host = url.host, !SSRFGuard.isInternalURL(url) else {
            throw RequestError.blockedInternalHost
        }
        if !skipDNS {
            let blocked = await Task.detached { SSRFGuard.resolvesToInternal(host) }.value
            guard !blocked else { throw RequestError.blockedInternalHost }
        }
    }

    private static func redirectTarget(from response: HTTPClientResponse, relativeTo current: URL) -> URL? {
        guard [301, 302, 303, 307, 308].contains(Int(response.status.code)),
              let location = response.headers.first(name: "Location") else { return nil }
        return URL(string: location, relativeTo: current)?.absoluteURL
    }

    private static func collectPrefix(_ body: HTTPClientResponse.Body, maxBytes: Int) async throws -> Data {
        guard maxBytes > 0 else { return Data() }
        var result = Data()
        result.reserveCapacity(maxBytes)
        for try await var chunk in body {
            let remaining = maxBytes - result.count
            guard remaining > 0 else { break }
            if chunk.readableBytes <= remaining {
                result.append(contentsOf: chunk.readableBytesView)
            } else if let slice = chunk.readSlice(length: remaining) {
                result.append(contentsOf: slice.readableBytesView)
                break
            }
        }
        return result
    }
}
