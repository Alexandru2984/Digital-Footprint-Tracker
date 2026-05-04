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

        let mimeMessage = """
            From: Digital Footprint Tracker <\(from)>
            To: \(to)
            Subject: \(subject)
            MIME-Version: 1.0
            Content-Type: text/plain; charset=utf-8

            \(body)
            """

        let port = Int(portStr) ?? 587
        let protocol_ = port == 465 ? "smtps" : "smtp"
        let sslFlag = port == 465 ? "--ssl" : "--ssl-reqd"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = [
            "--url", "\(protocol_)://\(host):\(port)",
            sslFlag,
            "--mail-from", from,
            "--mail-rcpt", to,
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
}
