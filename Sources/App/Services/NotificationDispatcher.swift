import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum NotificationChannel: String, Codable, CaseIterable, Hashable, Sendable {
    case webhook, discord, telegram, slack, email
}

enum NotificationDeliveryOutcome: String, Codable, CaseIterable, Hashable, Sendable {
    case succeeded, failed, skipped
}

struct NotificationDelivery: Content, Equatable {
    let channel: NotificationChannel
    let outcome: NotificationDeliveryOutcome
}

enum NotificationFailureDisposition: String, Codable, Sendable {
    case transient
    case permanent
}

struct NotificationAttemptResult: Equatable, Sendable {
    let outcome: NotificationDeliveryOutcome
    let failureDisposition: NotificationFailureDisposition?
    let failureCode: String?

    static let succeeded = NotificationAttemptResult(
        outcome: .succeeded, failureDisposition: nil, failureCode: nil
    )
    static let skipped = NotificationAttemptResult(
        outcome: .skipped, failureDisposition: nil, failureCode: nil
    )

    static func failed(
        _ disposition: NotificationFailureDisposition,
        code: String
    ) -> NotificationAttemptResult {
        .init(outcome: .failed, failureDisposition: disposition, failureCode: code)
    }

    var isRetryable: Bool {
        outcome == .failed && failureDisposition == .transient
    }
}

struct NotificationDispatcher {
    /// Send notification to all configured channels for a user.
    @discardableResult
    static func notify(
        user: User,
        title: String,
        message: String,
        scanID: UUID?,
        app: Application,
        metrics: MetricsRegistry = .shared
    ) async -> [NotificationDelivery] {
        var deliveries: [NotificationDelivery] = []
        for channel in NotificationChannel.allCases {
            let attempt = await deliver(
                channel: channel,
                user: user,
                title: title,
                message: message,
                webhookBody: nil,
                scanID: scanID,
                deliveryID: nil,
                app: app,
                metrics: metrics
            )
            deliveries.append(.init(channel: channel, outcome: attempt.outcome))
        }
        return deliveries
    }

    static func deliver(
        channel: NotificationChannel,
        user: User,
        title: String,
        message: String,
        webhookBody: String?,
        scanID: UUID?,
        deliveryID: UUID?,
        app: Application,
        metrics: MetricsRegistry = .shared
    ) async -> NotificationAttemptResult {
        let result: NotificationAttemptResult
        do {
            switch channel {
            case .webhook:
                guard let rawURL = try user.webhookURL else {
                    result = .skipped
                    break
                }
                guard let url = URL(string: rawURL),
                      let data = genericWebhookBody(
                        title: title,
                        message: message,
                        scanID: scanID,
                        webhookBody: webhookBody,
                        deliveryID: deliveryID
                      ) else {
                    result = .failed(.permanent, code: "invalid_payload_or_destination")
                    break
                }
                result = await sendWebhook(
                    url: url, data: data, deliveryID: deliveryID, app: app
                )

            case .discord:
                guard let rawURL = try user.discordWebhookURL else {
                    result = .skipped
                    break
                }
                guard let url = URL(string: rawURL),
                      let data = jsonData([
                        "embeds": [[
                            "title": title,
                            "description": message,
                            "color": 5793266,
                            "footer": ["text": "Digital Footprint Tracker"]
                        ]]
                      ]) else {
                    result = .failed(.permanent, code: "invalid_payload_or_destination")
                    break
                }
                result = await sendWebhook(
                    url: url, data: data, deliveryID: deliveryID, app: app
                )

            case .telegram:
                let token = try user.telegramBotToken
                let chatID = try user.telegramChatID
                if token == nil, chatID == nil {
                    result = .skipped
                } else if let token, let chatID, !token.isEmpty, !chatID.isEmpty {
                    result = await sendTelegram(
                        token: token,
                        chatID: chatID,
                        text: "**\(title)**\n\(message)",
                        deliveryID: deliveryID,
                        app: app
                    )
                } else {
                    result = .failed(.permanent, code: "incomplete_credentials")
                }

            case .slack:
                guard let rawURL = try user.slackWebhookURL else {
                    result = .skipped
                    break
                }
                guard let url = URL(string: rawURL),
                      let data = jsonData([
                        "blocks": [[
                            "type": "section",
                            "text": ["type": "mrkdwn", "text": "*\(title)*\n\(message)"]
                        ]]
                      ]) else {
                    result = .failed(.permanent, code: "invalid_payload_or_destination")
                    break
                }
                result = await sendWebhook(
                    url: url, data: data, deliveryID: deliveryID, app: app
                )

            case .email:
                let outcome = await EmailService.send(
                    to: user.email, subject: title, body: message, app: app
                )
                switch outcome {
                case .succeeded: result = .succeeded
                case .skipped: result = .skipped
                case .failed: result = .failed(.transient, code: "smtp_delivery_failed")
                }
            }
        } catch let failure as FieldCrypto.DecryptionFailure {
            await SensitiveFieldFailureReporter.report(
                failure,
                app: app,
                context: "notification_\(channel.rawValue)"
            )
            result = .failed(.permanent, code: "credential_unreadable")
        } catch {
            result = .failed(.permanent, code: "invalid_channel_configuration")
        }

        await metrics.recordNotificationDelivery(channel: channel, outcome: result.outcome)
        return result
    }

    private static func sendWebhook(
        url: URL,
        data: Data,
        deliveryID: UUID?,
        app: Application
    ) async -> NotificationAttemptResult {
        let destination = redactedDestination(url)
        // Cheap structural reject first; SafeHTTP adds the DNS-resolution and
        // redirect-chain checks that defeat rebinding-style SSRF bypasses.
        guard !SSRFGuard.isInternalURL(url) else {
            app.logger.warning("Blocked outbound webhook to internal host: \(destination)")
            return .failed(.permanent, code: "blocked_destination")
        }
        do {
            var headers: [String: String] = [:]
            if let deliveryID {
                headers["Idempotency-Key"] = deliveryID.uuidString.lowercased()
                headers["X-Notification-Delivery-ID"] = deliveryID.uuidString.lowercased()
            }
            let response = try await SafeHTTP.post(
                url: url, body: data, additionalHeaders: headers, on: app
            )
            guard (200..<300).contains(response.status) else {
                app.logger.debug("Webhook delivery to \(destination) returned HTTP \(response.status).")
                let transient = response.status == 408 || response.status == 425
                    || response.status == 429 || (500..<600).contains(response.status)
                return .failed(
                    transient ? .transient : .permanent,
                    code: "http_\(response.status)"
                )
            }
            return .succeeded
        } catch SafeHTTP.SafeHTTPError.blockedInternalHost {
            app.logger.warning("Blocked outbound webhook: \(destination) resolved to an internal address.")
            return .failed(.permanent, code: "blocked_destination")
        } catch SafeHTTP.SafeHTTPError.badURL {
            return .failed(.permanent, code: "invalid_destination")
        } catch {
            // HTTP client errors may embed the complete request URL. Webhook
            // paths frequently contain signing secrets, so never interpolate
            // the error object into logs for a user-configured destination.
            app.logger.debug("Webhook delivery to \(destination) failed.")
            return .failed(.transient, code: "network_error")
        }
    }

    private static func redactedDestination(_ url: URL) -> String {
        guard let scheme = url.scheme, let host = url.host else { return "invalid-destination" }
        return "\(scheme.lowercased())://\(host.lowercased())\(url.port.map { ":\($0)" } ?? "")"
    }

    private static func sendTelegram(
        token: String,
        chatID: String,
        text: String,
        deliveryID: UUID?,
        app: Application
    ) async -> NotificationAttemptResult {
        guard let url = URL(string: "https://api.telegram.org/bot\(token)/sendMessage") else {
            return .failed(.permanent, code: "invalid_destination")
        }
        let payload: [String: Any] = ["chat_id": chatID, "text": text, "parse_mode": "Markdown"]
        guard let data = jsonData(payload) else {
            return .failed(.permanent, code: "invalid_payload")
        }
        return await sendWebhook(url: url, data: data, deliveryID: deliveryID, app: app)
    }

    private static func genericWebhookBody(
        title: String,
        message: String,
        scanID: UUID?,
        webhookBody: String?,
        deliveryID: UUID?
    ) -> Data? {
        var payload: [String: Any]
        if let webhookBody,
           let data = webhookBody.data(using: .utf8),
           let decoded = try? JSONSerialization.jsonObject(with: data),
           let object = decoded as? [String: Any] {
            payload = object
        } else if webhookBody != nil {
            return nil
        } else {
            payload = ["title": title, "message": message]
            if let scanID { payload["scanID"] = scanID.uuidString.lowercased() }
        }
        if let deliveryID {
            payload["deliveryID"] = deliveryID.uuidString.lowercased()
        }
        return jsonData(payload)
    }

    private static func jsonData(_ payload: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }
}
