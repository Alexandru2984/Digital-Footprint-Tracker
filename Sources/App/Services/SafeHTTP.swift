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

    private lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 10
        cfg.timeoutIntervalForResource = 15
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()

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
