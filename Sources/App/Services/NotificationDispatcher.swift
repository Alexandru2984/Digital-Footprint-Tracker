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

        // 1. Existing webhook (backward compat)
        let webhookOutcome: NotificationDeliveryOutcome
        if let webhookURL = user.webhookURL, let url = URL(string: webhookURL) {
            var payload: [String: Any] = ["title": title, "message": message]
            if let sid = scanID { payload["scanID"] = sid.uuidString }
            webhookOutcome = await sendWebhook(url: url, payload: payload, app: app)
        } else {
            webhookOutcome = user.webhookURL == nil ? .skipped : .failed
        }
        await metrics.recordNotificationDelivery(channel: .webhook, outcome: webhookOutcome)
        deliveries.append(.init(channel: .webhook, outcome: webhookOutcome))

        // 2. Discord
        let discordOutcome: NotificationDeliveryOutcome
        if let discordURL = user.discordWebhookURL, let url = URL(string: discordURL) {
            let embed: [String: Any] = [
                "title": title,
                "description": message,
                "color": 5793266,
                "footer": ["text": "Digital Footprint Tracker"]
            ]
            let payload: [String: Any] = ["embeds": [embed]]
            discordOutcome = await sendWebhook(url: url, payload: payload, app: app)
        } else {
            discordOutcome = user.discordWebhookURL == nil ? .skipped : .failed
        }
        await metrics.recordNotificationDelivery(channel: .discord, outcome: discordOutcome)
        deliveries.append(.init(channel: .discord, outcome: discordOutcome))

        // 3. Telegram
        let telegramOutcome: NotificationDeliveryOutcome
        if let token = user.telegramBotToken, let chatID = user.telegramChatID, !token.isEmpty, !chatID.isEmpty {
            telegramOutcome = await sendTelegram(
                token: token, chatID: chatID, text: "**\(title)**\n\(message)", app: app
            )
        } else if user.telegramBotToken == nil, user.telegramChatID == nil {
            telegramOutcome = .skipped
        } else {
            telegramOutcome = .failed
        }
        await metrics.recordNotificationDelivery(channel: .telegram, outcome: telegramOutcome)
        deliveries.append(.init(channel: .telegram, outcome: telegramOutcome))

        // 4. Slack
        let slackOutcome: NotificationDeliveryOutcome
        if let slackURL = user.slackWebhookURL, let url = URL(string: slackURL) {
            let payload: [String: Any] = [
                "blocks": [
                    ["type": "section", "text": ["type": "mrkdwn", "text": "*\(title)*\n\(message)"]]
                ]
            ]
            slackOutcome = await sendWebhook(url: url, payload: payload, app: app)
        } else {
            slackOutcome = user.slackWebhookURL == nil ? .skipped : .failed
        }
        await metrics.recordNotificationDelivery(channel: .slack, outcome: slackOutcome)
        deliveries.append(.init(channel: .slack, outcome: slackOutcome))

        // 5. Email
        let emailOutcome = await EmailService.send(
            to: user.email, subject: title, body: message, app: app
        )
        await metrics.recordNotificationDelivery(channel: .email, outcome: emailOutcome)
        deliveries.append(.init(channel: .email, outcome: emailOutcome))

        return deliveries
    }

    private static func sendWebhook(
        url: URL, payload: [String: Any], app: Application
    ) async -> NotificationDeliveryOutcome {
        let destination = redactedDestination(url)
        // Cheap structural reject first; SafeHTTP adds the DNS-resolution and
        // redirect-chain checks that defeat rebinding-style SSRF bypasses.
        guard !SSRFGuard.isInternalURL(url) else {
            app.logger.warning("Blocked outbound webhook to internal host: \(destination)")
            return .failed
        }
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return .failed }
        do {
            let response = try await SafeHTTP.post(url: url, body: data, on: app)
            guard (200..<300).contains(response.status) else {
                app.logger.debug("Webhook delivery to \(destination) returned HTTP \(response.status).")
                return .failed
            }
            return .succeeded
        } catch SafeHTTP.SafeHTTPError.blockedInternalHost {
            app.logger.warning("Blocked outbound webhook: \(destination) resolved to an internal address.")
            return .failed
        } catch {
            // HTTP client errors may embed the complete request URL. Webhook
            // paths frequently contain signing secrets, so never interpolate
            // the error object into logs for a user-configured destination.
            app.logger.debug("Webhook delivery to \(destination) failed.")
            return .failed
        }
    }

    private static func redactedDestination(_ url: URL) -> String {
        guard let scheme = url.scheme, let host = url.host else { return "invalid-destination" }
        return "\(scheme.lowercased())://\(host.lowercased())\(url.port.map { ":\($0)" } ?? "")"
    }

    private static func sendTelegram(
        token: String, chatID: String, text: String, app: Application
    ) async -> NotificationDeliveryOutcome {
        guard let url = URL(string: "https://api.telegram.org/bot\(token)/sendMessage") else {
            return .failed
        }
        let payload: [String: Any] = ["chat_id": chatID, "text": text, "parse_mode": "Markdown"]
        return await sendWebhook(url: url, payload: payload, app: app)
    }
}
