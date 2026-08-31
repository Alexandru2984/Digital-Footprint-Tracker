import Vapor

extension Environment {
    /// Whether this process should be treated as a real deployment.
    ///
    /// Every security control that can be relaxed used to be keyed to
    /// `environment == .production` — the literal name. Vapor accepts any name
    /// on `--env`, and defaults to `.development` when the flag is absent, so
    /// *anything* that was not spelled exactly `production` relaxed all of them
    /// at once: field encryption became optional and sensitive columns were
    /// written in plaintext, audit entries went unsigned, CSRF provenance was
    /// no longer required, `localhost` was accepted as an origin, CORS opened
    /// to `*`, the database password fell back to a hardcoded default, and
    /// migrations ran automatically on boot.
    ///
    /// Two things reach that state without anyone deciding to: a `staging` or
    /// `canary` deployment named honestly, and a production unit that loses its
    /// `--env production` flag — which still connects to whatever
    /// `DATABASE_HOST` says, and would keep serving.
    ///
    /// So the test is inverted. Only the two environments that are
    /// definitionally not a deployment relax anything; every other name,
    /// including ones that do not exist yet, is treated as real. The safe
    /// direction for an unknown environment is strict.
    var isRealDeployment: Bool {
        self != .development && self != .testing
    }
}
