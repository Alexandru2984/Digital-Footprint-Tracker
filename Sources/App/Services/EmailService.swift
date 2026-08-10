import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct EmailService {
    static func send(to: String, subject: String, body: String, app: Application) async {
        // Never deliver real mail from the test environment. `swift test` boots
        // with the box's `.env` (SMTP_* point at Resend for micutu.com), so
        // without this guard every test that registers a user would send a live
        // email to a fixture address — 422 on `@example.com`, guaranteed bounce
        // on domains with no MX — and wreck the domain's sender reputation for
        // every project that mails from it. Tests exercise formatting, not
        // delivery. To exercise real delivery on purpose, use a non-test env and
        // Resend's sink addresses (delivered@resend.dev / bounced@resend.dev).
        guard app.environment != .testing else {
            app.logger.debug("EmailService: test environment — skipping real delivery to \(EmailAddress.redactedDomain(to))")
            return
        }
        guard let host = Environment.get("SMTP_HOST"),
              let portStr = Environment.get("SMTP_PORT"),
              let user = Environment.get("SMTP_USER"),
              let pass = Environment.get("SMTP_PASS"),
              let from = Environment.get("SMTP_FROM") else {
            app.logger.warning("EmailService: SMTP not configured; skipping one email delivery")
            return
        }

        guard let safeFrom = EmailAddress.normalize(from),
              let safeTo = EmailAddress.normalize(to) else {
            app.logger.error("EmailService: rejected an invalid sender or recipient address")
            return
        }
        let safeSubject = boundedUTF8(sanitizeHeader(subject), maxBytes: 512)
        // Body: drop NULs and normalize any line endings to CRLF (some MUAs
        // produce LF or CR alone; SMTP requires CRLF throughout, including
        // body lines for strict relays). Bound it so a malformed notification
        // cannot turn curl's stdin into an unbounded memory/traffic sink.
        let safeBody = boundedUTF8(body, maxBytes: 64 * 1_024)
            .replacingOccurrences(of: "\0", with: "")
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r",   with: "\n")
            .replacingOccurrences(of: "\n",   with: "\r\n")

        // Build the MIME message with explicit CRLF separators between headers
        // and between header/body — required by RFC 5321/5322. The previous
        // Swift multiline literal produced LF-only line endings, which strict
        // SMTP relays may reject as malformed.
        let mimeMessage = [
            "From: Digital Footprint Tracker <\(safeFrom)>",
            "To: \(safeTo)",
            "Subject: \(safeSubject)",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
            "",
            safeBody,
        ].joined(separator: "\r\n")

        guard let port = Int(portStr), (1...65_535).contains(port) else {
            app.logger.error("EmailService: SMTP_PORT is invalid")
            return
        }
        let protocol_ = port == 465 ? "smtps" : "smtp"
        let sslFlag = port == 465 ? "--ssl" : "--ssl-reqd"
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let hostCharacters = CharacterSet.alphanumerics.union(.init(charactersIn: ".:-"))
        guard !trimmedHost.isEmpty, trimmedHost.utf8.count <= 253,
              trimmedHost.unicodeScalars.allSatisfy(hostCharacters.contains) else {
            app.logger.error("EmailService: SMTP_HOST is invalid")
            return
        }
        var smtpComponents = URLComponents()
        smtpComponents.scheme = protocol_
        smtpComponents.host = trimmedHost
        smtpComponents.port = port
        guard let smtpURL = smtpComponents.url else {
            app.logger.error("EmailService: SMTP endpoint is invalid")
            return
        }

        // Keep credentials in a 0700 directory and out of argv/environment.
        // Quoted netrc values prevent whitespace from changing its grammar.
        guard let safeUser = netrcValue(user), let safePass = netrcValue(pass) else {
            app.logger.error("EmailService: SMTP credentials contain unsupported characters")
            return
        }
        let processHome = FileManager.default.temporaryDirectory
            .appendingPathComponent("dft-smtp-\(UUID().uuidString)", isDirectory: true)
        let credsFile = processHome.appendingPathComponent("credentials.netrc")
        let netrcBody = "default\n  login \(safeUser)\n  password \(safePass)\n"
        do {
            try FileManager.default.createDirectory(
                at: processHome,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
            try netrcBody.write(to: credsFile, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o600)],
                ofItemAtPath: credsFile.path
            )
        } catch {
            app.logger.error("EmailService: failed to prepare private SMTP credentials")
            try? FileManager.default.removeItem(at: processHome)
            return
        }
        defer { try? FileManager.default.removeItem(at: processHome) }

        // Resolve a curl binary. The previous hardcoded path failed silently
        // on systems where curl lives elsewhere (macOS dev installs, alpine
        // containers, custom toolchains). Order: CURL_PATH env → /usr/bin →
        // /usr/local/bin. Log clearly if nothing is found.
        let curlCandidates = [Environment.get("CURL_PATH"), "/usr/bin/curl", "/usr/local/bin/curl"]
            .compactMap { $0 }
        guard let curlPath = curlCandidates.first(where: {
            $0.hasPrefix("/") && FileManager.default.isExecutableFile(atPath: $0)
        }) else {
            app.logger.error("EmailService: no trusted executable curl was found")
            return
        }
        let arguments = [
            // --disable must be the first option to prevent ~/.curlrc from
            // changing the request or exfiltrating the netrc credential.
            "--disable",
            "--proto", "=smtp,smtps",
            "--url", smtpURL.absoluteString,
            sslFlag,
            "--mail-from", safeFrom,
            "--mail-rcpt", safeTo,
            "--netrc-file", credsFile.path,
            "--upload-file", "-",
            "--silent",
            "--max-time", "15"
        ]

        do {
            let execution = try await BoundedProcess.run(
                executable: curlPath,
                arguments: arguments,
                environment: [
                    "PATH": "/usr/bin:/usr/local/bin",
                    "HOME": processHome.path,
                    "TMPDIR": processHome.path,
                    "LANG": "C.UTF-8",
                ],
                stdin: Data(mimeMessage.utf8),
                timeout: 20,
                maxOutputBytes: 32 * 1_024,
                privateTemporaryDirectory: false
            )
            if !execution.succeeded {
                // Surface hard rejections (e.g. Resend's 422 for an invalid
                // recipient) at error level so a silent delivery gap is visible.
                // Note: an accepted message that bounces later (no MX, etc.) exits
                // 0 here — those only show up via the provider's bounce webhook.
                app.logger.error("""
                    EmailService: SMTP delivery FAILED — nothing was delivered \
                    (curl exit \(execution.exitStatus), recipient domain: \(EmailAddress.redactedDomain(safeTo))).
                    """)
            }
        } catch {
            app.logger.error("EmailService: failed to start SMTP delivery subprocess (recipient domain: \(EmailAddress.redactedDomain(safeTo)))")
        }
    }

    /// Removes CR, LF, and NULL characters from a single-line mail header value.
    private static func sanitizeHeader(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\0", with: "")
    }

    private static func boundedUTF8(_ value: String, maxBytes: Int) -> String {
        let data = Data(value.utf8)
        guard data.count > maxBytes else { return value }
        return String(decoding: data.prefix(maxBytes), as: UTF8.self)
    }

    private static func netrcValue(_ value: String) -> String? {
        guard !value.isEmpty, value.utf8.count <= 1_024,
              !value.contains("\r"), !value.contains("\n"), !value.contains("\0") else {
            return nil
        }
        return "\"" + value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
