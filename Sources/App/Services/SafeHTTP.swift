import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Outbound HTTP client for user-controlled destinations (webhooks, Discord /
/// Slack / Telegram). Hardened against SSRF in two ways the bare
/// `URLSession.shared` is not:
///
///   1. **Pre-flight DNS check** — the target host is resolved and rejected if
///      any answer is internal (`SSRFGuard.resolvesToInternal`), closing the
///      DNS-record-points-at-127.0.0.1 / metadata bypass.
///   2. **Redirect validation** — every 3xx hop is re-checked, so a public URL
///      cannot 302 the request onto `http://169.254.169.254/`.
///
/// Residual risk: a TOCTOU window remains between the pre-flight resolution and
/// the kernel connect (classic DNS rebinding). Fully closing it requires pinning
/// the resolved IP and connecting to it with the original Host header, which
/// URLSession does not expose. For this project's threat model (low-volume,
/// user-supplied webhook URLs) the pre-flight + redirect guard is the accepted
/// mitigation. `getaddrinfo` is blocking; calls here are infrequent.
final class SafeHTTP: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = SafeHTTP()

    enum SafeHTTPError: Error { case blockedInternalHost, badURL }

    // Eagerly initialised (not `lazy`): a `lazy var` is not thread-safe, and a
    // full scan runs several SafeHTTP users (WebPosture, ExposedFiles, …)
    // concurrently — racing the first access could double-init or hang. Building
    // it once in `init` removes that race. IUO because the delegate is `self`,
    // which isn't available until after `super.init()`.
    private var session: URLSession!

    override init() {
        super.init()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 10
        cfg.timeoutIntervalForResource = 15
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    /// POST `body` to `url`. Throws `blockedInternalHost` if the destination (or
    /// any redirect hop) resolves to a private/loopback/link-local address.
    func post(url: URL, body: Data, contentType: String = "application/json", timeout: TimeInterval = 10) async throws {
        guard let host = url.host, !host.isEmpty else { throw SafeHTTPError.badURL }
        guard !SSRFGuard.resolvesToInternal(host) else { throw SafeHTTPError.blockedInternalHost }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue(contentType, forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        req.timeoutInterval = timeout
        _ = try await session.data(for: req)
    }

    /// Response metadata from a guarded GET — enough for header/posture analysis.
    struct Response: Sendable {
        let status: Int
        let headers: [String: String]   // header names lowercased
        let finalURL: URL?
        /// First ~8 KB of the body decoded as UTF-8 (lossy) — enough to signature-
        /// match exposed files without pulling a whole response into memory. Nil
        /// unless the caller requested the body.
        let bodyPrefix: String?

        init(status: Int, headers: [String: String], finalURL: URL?, bodyPrefix: String? = nil) {
            self.status = status
            self.headers = headers
            self.finalURL = finalURL
            self.bodyPrefix = bodyPrefix
        }
    }

    /// GET `url` and return its status + response headers, with the same SSRF
    /// protection as `post` (pre-flight DNS check + redirect re-validation). Used by
    /// the web-posture plugin to inspect security headers on a user-supplied host.
    /// - Parameter hostPreChecked: when true, skip the (blocking `getaddrinfo`)
    ///   pre-flight DNS check because the caller already verified this exact host
    ///   is public. Redirect hops are still re-validated by the delegate. Callers
    ///   use this to fetch many paths on ONE already-checked host without firing a
    ///   storm of concurrent blocking resolves that would starve the async pool.
    func get(url: URL, timeout: TimeInterval = 10, wantBody: Bool = false, hostPreChecked: Bool = false) async throws -> Response {
        guard let host = url.host, !host.isEmpty else { throw SafeHTTPError.badURL }
        if !hostPreChecked {
            guard !SSRFGuard.resolvesToInternal(host) else { throw SafeHTTPError.blockedInternalHost }
        }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = timeout
        req.setValue("Digital-Footprint-Tracker/1.0 (+https://swift.micutu.com)", forHTTPHeaderField: "User-Agent")
        if wantBody {
            // Only the first 8 KB is ever inspected. Ask for just that so a huge
            // response (e.g. a multi-GB exposed DB dump) can't be buffered whole
            // into memory. Servers that ignore Range fall back to a full body,
            // still bounded by the resource timeout.
            req.setValue("bytes=0-8191", forHTTPHeaderField: "Range")
        }

        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw SafeHTTPError.badURL }

        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            headers[String(describing: key).lowercased()] = String(describing: value)
        }
        let bodyPrefix = wantBody ? String(decoding: data.prefix(8192), as: UTF8.self) : nil
        return Response(status: http.statusCode, headers: headers, finalURL: http.url, bodyPrefix: bodyPrefix)
    }

    // MARK: - URLSessionTaskDelegate

    /// Re-validate the destination of every redirect; refuse to follow one that
    /// points at an internal host (returning nil stops the redirect chain).
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        if let host = request.url?.host, SSRFGuard.resolvesToInternal(host) {
            completionHandler(nil)
        } else {
            completionHandler(request)
        }
    }
}
