import Vapor
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct EmailService {
    static func send(to: String, subject: String, body: String, app: Application) async {
        guard let host = Environment.get("SMTP_HOST"),
              let portStr = Environment.get("SMTP_PORT"),
              let user = Environment.get("SMTP_USER"),
              let pass = Environment.get("SMTP_PASS"),
              let from = Environment.get("SMTP_FROM") else {
            app.logger.warning("EmailService: SMTP not configured, skipping email to \(to)")
            return
        }

        // Strip CRLF / bare CR to prevent mail header injection.
        let safeFrom    = sanitizeHeader(from)
        let safeTo      = sanitizeHeader(to)
        let safeSubject = sanitizeHeader(subject)
        // Body CRLF is fine (multiline content), only strip NULL bytes.
        let safeBody    = body.replacingOccurrences(of: "\0", with: "")

        let mimeMessage = """
            From: Digital Footprint Tracker <\(safeFrom)>
            To: \(safeTo)
            Subject: \(safeSubject)
            MIME-Version: 1.0
            Content-Type: text/plain; charset=utf-8

            \(safeBody)
            """

        let port = Int(portStr) ?? 587
        let protocol_ = port == 465 ? "smtps" : "smtp"
        let sslFlag = port == 465 ? "--ssl" : "--ssl-reqd"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = [
            "--url", "\(protocol_)://\(host):\(port)",
            sslFlag,
            "--mail-from", safeFrom,
            "--mail-rcpt", safeTo,
            "--user", "\(user):\(pass)",
            "--upload-file", "-",
            "--silent",
            "--max-time", "15"
        ]

        let inputPipe = Pipe()
        process.standardInput = inputPipe

        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                do {
                    try process.run()
                    inputPipe.fileHandleForWriting.write(Data(mimeMessage.utf8))
                    inputPipe.fileHandleForWriting.closeFile()
                    process.waitUntilExit()
                    if process.terminationStatus != 0 {
                        app.logger.warning("EmailService: curl exited with status \(process.terminationStatus)")
                    }
                } catch {
                    app.logger.error("EmailService: failed to run curl: \(error)")
                }
                continuation.resume()
            }
        }
    }

    /// Removes CR, LF, and NULL characters from a single-line mail header value.
    private static func sanitizeHeader(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\0", with: "")
    }
}

