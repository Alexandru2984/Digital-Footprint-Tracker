import Foundation
import Vapor

/// Outbound HTTP facade for user-controlled destinations. Every request is
/// streamed through `OutboundHTTP`, DNS-checked, size-bounded, and has each
/// redirect hop validated before connecting.
enum SafeHTTP {
    enum SafeHTTPError: Error { case blockedInternalHost, badURL }

    struct Response: Sendable {
        let status: Int
        let headers: [String: String]
        let finalURL: URL?
        let bodyPrefix: String?
    }

    @discardableResult
    static func post(
        url: URL,
        body: Data,
        contentType: String = "application/json",
        additionalHeaders: [String: String] = [:],
        timeout: TimeInterval = 10,
        on app: Application
    ) async throws -> Response {
        do {
            var headers = additionalHeaders
            // The content type is owned by the caller's typed argument, not by
            // the optional metadata map, so it cannot be shadowed accidentally.
            headers["Content-Type"] = contentType
            let response = try await OutboundHTTP.request(
                url,
                method: .POST,
                headers: headers,
                body: body,
                timeout: timeout,
                bodyMode: .prefix(maxBytes: 1_024),
                maxRedirects: 0,
                on: app
            )
            return Response(
                status: response.status,
                headers: response.headers,
                finalURL: response.finalURL,
                bodyPrefix: String(decoding: response.data, as: UTF8.self)
            )
        } catch OutboundHTTP.RequestError.blockedInternalHost {
            throw SafeHTTPError.blockedInternalHost
        } catch OutboundHTTP.RequestError.invalidURL {
            throw SafeHTTPError.badURL
        }
    }

    static func get(
        url: URL,
        timeout: TimeInterval = 10,
        wantBody: Bool = false,
        hostPreChecked: Bool = false,
        on app: Application
    ) async throws -> Response {
        do {
            let bodyMode: OutboundHTTP.BodyMode = .prefix(maxBytes: wantBody ? 8_192 : 0)
            let response = try await OutboundHTTP.request(
                url,
                timeout: timeout,
                bodyMode: bodyMode,
                maxRedirects: 3,
                hostPreChecked: hostPreChecked,
                on: app
            )
            return Response(
                status: response.status,
                headers: response.headers,
                finalURL: response.finalURL,
                bodyPrefix: wantBody ? String(decoding: response.data, as: UTF8.self) : nil
            )
        } catch OutboundHTTP.RequestError.blockedInternalHost {
            throw SafeHTTPError.blockedInternalHost
        } catch OutboundHTTP.RequestError.invalidURL {
            throw SafeHTTPError.badURL
        }
    }
}
