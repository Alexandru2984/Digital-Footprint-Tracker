import ConsoleKit
import Logging
import Vapor

/// Puts the sd-daemon priority prefix (`<3>` for error, ...) at the start of
/// each log line, so journald records the level instead of logging everything
/// at `info`. Without it `journalctl -p err` matched nothing even on a day with
/// errors, and any check filtering by priority was blind. journald strips the
/// prefix, so the visible line is unchanged.
public struct JournalPriorityFragment: LoggerFragment {
    public init() {}

    public func write(_ record: inout LogRecord, to output: inout FragmentOutput) {
        output += "<\(Self.priority(record.level))>".consoleText()
    }

    /// syslog(3) priorities, as sd-daemon(3) reads them.
    static func priority(_ level: Logger.Level) -> Int {
        switch level {
        case .trace, .debug: return 7
        case .info: return 6
        case .notice: return 5
        case .warning: return 4
        case .error: return 3
        case .critical: return 2
        }
    }

    /// systemd sets `JOURNAL_STREAM` only when stdout goes to the journal, so a
    /// terminal, a pipe or a test run keeps the plain format.
    public static var stdoutIsJournal: Bool {
        Environment.get("JOURNAL_STREAM").map { !$0.isEmpty } ?? false
    }
}
