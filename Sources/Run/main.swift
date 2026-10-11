import Vapor
import App

@main
enum Run {
    static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env) { level in
            let console = Terminal()
            let journal = JournalPriorityFragment.stdoutIsJournal
            return { label -> LogHandler in
                guard journal else { return ConsoleLogger(label: label, console: console, level: level) }
                return ConsoleFragmentLogger(
                    fragment: JournalPriorityFragment().and(defaultLoggerFragment()),
                    label: label, console: console, level: level)
            }
        }

        let app = try await Application.make(env)
        do {
            try await configure(app)
            try await app.execute()
        } catch {
            // Async commands still install Vapor's ServeCommand internally.
            // Synchronous shutdown from this async entrypoint can destroy it
            // before its async lifecycle hook runs and trigger an assertion.
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }
}
