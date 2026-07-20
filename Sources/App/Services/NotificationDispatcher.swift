import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct NotificationDispatcher {
    /// Send notification to all configured channels for a user.
    static func notify(user: User, title: String, message: String, scanID: UUID?, app: Application) async {
        // 1. Existing webhook (backward compat)
        if let webhookURL = user.webhookURL, let url = URL(string: webhookURL) {
            var payload: [String: Any] = ["title": title, "message": message]
            if let sid = scanID { payload["scanID"] = sid.uuidString }
            await sendWebhook(url: url, payload: payload, app: app)
            await MetricsRegistry.shared.incNotificationSent(channel: "webhook")
        }
        // 2. Discord
        if let discordURL = user.discordWebhookURL, let url = URL(string: discordURL) {
            let embed: [String: Any] = [
                "title": title,
                "description": message,
                "color": 5793266,
                "footer": ["text": "Digital Footprint Tracker"]
            ]
            let payload: [String: Any] = ["embeds": [embed]]
            await sendWebhook(url: url, payload: payload, app: app)
            await MetricsRegistry.shared.incNotificationSent(channel: "discord")
        }
        // 3. Telegram
        if let token = user.telegramBotToken, let chatID = user.telegramChatID, !token.isEmpty, !chatID.isEmpty {
            await sendTelegram(token: token, chatID: chatID, text: "**\(title)**\n\(message)", app: app)
            await MetricsRegistry.shared.incNotificationSent(channel: "telegram")
        }
        // 4. Slack
        if let slackURL = user.slackWebhookURL, let url = URL(string: slackURL) {
            let payload: [String: Any] = [
                "blocks": [
                    ["type": "section", "text": ["type": "mrkdwn", "text": "*\(title)*\n\(message)"]]
                ]
            ]
            await sendWebhook(url: url, payload: payload, app: app)
            await MetricsRegistry.shared.incNotificationSent(channel: "slack")
        }
        // 5. Email
        await EmailService.send(to: user.email, subject: title, body: message, app: app)
        await MetricsRegistry.shared.incNotificationSent(channel: "email")
    }

    private static func sendWebhook(url: URL, payload: [String: Any], app: Application) async {
        let destination = redactedDestination(url)
        // Cheap structural reject first; SafeHTTP adds the DNS-resolution and
        // redirect-chain checks that defeat rebinding-style SSRF bypasses.
        guard !SSRFGuard.isInternalURL(url) else {
            app.logger.warning("Blocked outbound webhook to internal host: \(destination)")
            return
        }
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
        do {
            try await SafeHTTP.post(url: url, body: data, on: app)
        } catch SafeHTTP.SafeHTTPError.blockedInternalHost {
            app.logger.warning("Blocked outbound webhook: \(destination) resolved to an internal address.")
        } catch {
            // HTTP client errors may embed the complete request URL. Webhook
            // paths frequently contain signing secrets, so never interpolate
            // the error object into logs for a user-configured destination.
            app.logger.debug("Webhook delivery to \(destination) failed.")
        }
    }

    private static func redactedDestination(_ url: URL) -> String {
        guard let scheme = url.scheme, let host = url.host else { return "invalid-destination" }
        return "\(scheme.lowercased())://\(host.lowercased())\(url.port.map { ":\($0)" } ?? "")"
    }

    private static func sendTelegram(token: String, chatID: String, text: String, app: Application) async {
        guard let url = URL(string: "https://api.telegram.org/bot\(token)/sendMessage") else { return }
        let payload: [String: Any] = ["chat_id": chatID, "text": text, "parse_mode": "Markdown"]
        await sendWebhook(url: url, payload: payload, app: app)
    }
}
