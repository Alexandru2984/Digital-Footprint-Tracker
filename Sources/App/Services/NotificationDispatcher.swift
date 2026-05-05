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
        }
        // 3. Telegram
        if let token = user.telegramBotToken, let chatID = user.telegramChatID, !token.isEmpty, !chatID.isEmpty {
            await sendTelegram(token: token, chatID: chatID, text: "**\(title)**\n\(message)", app: app)
        }
        // 4. Slack
        if let slackURL = user.slackWebhookURL, let url = URL(string: slackURL) {
            let payload: [String: Any] = [
                "blocks": [
                    ["type": "section", "text": ["type": "mrkdwn", "text": "*\(title)*\n\(message)"]]
                ]
            ]
            await sendWebhook(url: url, payload: payload, app: app)
        }
        // 5. Email
        await EmailService.send(to: user.email, subject: title, body: message, app: app)
    }

    private static func sendWebhook(url: URL, payload: [String: Any], app: Application) async {
        guard !isInternalURL(url) else {
            app.logger.warning("Blocked outbound webhook to internal host: \(url.host ?? url.absoluteString)")
            return
        }
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
        var urlReq = URLRequest(url: url)
        urlReq.httpMethod = "POST"
        urlReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlReq.httpBody = data
        urlReq.timeoutInterval = 10
        _ = try? await URLSession.shared.data(for: urlReq)
    }

    private static func sendTelegram(token: String, chatID: String, text: String, app: Application) async {
        // Decrypt token if encryption is available; fall back to raw value for legacy plaintext tokens
        let plainToken = TokenEncryption.decrypt(token) ?? token
        guard let url = URL(string: "https://api.telegram.org/bot\(plainToken)/sendMessage") else { return }
        let payload: [String: Any] = ["chat_id": chatID, "text": text, "parse_mode": "Markdown"]
        await sendWebhook(url: url, payload: payload, app: app)
    }
}
