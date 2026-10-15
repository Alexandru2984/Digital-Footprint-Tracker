import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// Runs a fixed executable without a shell, with an isolated environment,
/// bounded stdout, and a hard wall-clock deadline.
enum BoundedProcess {
    enum ConfigurationError: Error {
        case invalidExecutable
        case invalidLimits
    }

    struct Result: Sendable {
        let stdout: Data
        let exitStatus: Int32
        let timedOut: Bool
        let outputExceeded: Bool
        let outputReadFailed: Bool

        var succeeded: Bool {
            exitStatus == 0 && !timedOut && !outputExceeded && !outputReadFailed
        }
    }

    private final class CaptureState: @unchecked Sendable {
        private let lock = NSLock()
        private let maxBytes: Int
        private var output = Data()
        private var didExceed = false
        private var didTimeOut = false
        private var readFailed = false

        init(maxBytes: Int) {
            self.maxBytes = maxBytes
            output.reserveCapacity(min(maxBytes, 1_048_576))
        }

        /// Returns true exactly when this append first crosses the output cap.
        func append(_ chunk: Data) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            let remaining = max(0, maxBytes - output.count)
            if remaining > 0 { output.append(chunk.prefix(remaining)) }
            guard chunk.count > remaining, !didExceed else { return false }
            didExceed = true
            return true
        }

        func markTimedOut() {
            lock.lock()
            didTimeOut = true
            lock.unlock()
        }

        func markReadFailed() {
            lock.lock()
            readFailed = true
            lock.unlock()
        }

        func snapshot(exitStatus: Int32) -> Result {
            lock.lock()
            defer { lock.unlock() }
            return Result(
                stdout: output,
                exitStatus: exitStatus,
                timedOut: didTimeOut,
                outputExceeded: didExceed,
                outputReadFailed: readFailed
            )
        }
    }

    static func run(
        executable: String,
        arguments: [String] = [],
        environment: [String: String],
        stdin: Data = Data(),
        timeout: TimeInterval,
        maxOutputBytes: Int,
        privateTemporaryDirectory: Bool = true
    ) async throws -> Result {
        guard executable.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: executable) else {
            throw ConfigurationError.invalidExecutable
        }
        guard timeout > 0, timeout <= 300,
              maxOutputBytes >= 0, maxOutputBytes <= 32 * 1_024 * 1_024,
              stdin.count <= 16 * 1_024 * 1_024 else {
            throw ConfigurationError.invalidLimits
        }

        var childEnvironment = environment
        var temporaryDirectory: URL?
        if privateTemporaryDirectory {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("dft-process-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
            temporaryDirectory = directory
            childEnvironment["HOME"] = directory.path
            childEnvironment["TMPDIR"] = directory.path
        }
        defer {
            if let temporaryDirectory {
                try? FileManager.default.removeItem(at: temporaryDirectory)
            }
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = childEnvironment

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice

        try process.run()
        let state = CaptureState(maxBytes: maxOutputBytes)
        let processID = process.processIdentifier
        let exit = ExitState()

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let finish = ResumeOnce(continuation)
                let work = DispatchGroup()

                work.enter()
                DispatchQueue.global(qos: .utility).async {
                    defer {
                        try? outputPipe.fileHandleForReading.close()
                        work.leave()
                    }
                    // POSIX read, not `read(upToCount:)`: that one holds what
                    // arrived until the count fills or the pipe closes, so a
                    // pipe a leftover grandchild keeps open would hide output
                    // the child already wrote.
                    let descriptor = outputPipe.fileHandleForReading.fileDescriptor
                    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
                    while true {
                        let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
                        if count == 0 { break }
                        if count < 0 {
                            if errno == EINTR { continue }
                            state.markReadFailed()
                            stop(process, unless: exit)
                            break
                        }
                        if state.append(Data(buffer[0..<count])) { stop(process, unless: exit) }
                    }
                }

                work.enter()
                DispatchQueue.global(qos: .utility).async {
                    defer {
                        try? inputPipe.fileHandleForWriting.close()
                        work.leave()
                    }
                    if !stdin.isEmpty {
                        try? inputPipe.fileHandleForWriting.write(contentsOf: stdin)
                    }
                }

                // Not `waitUntilExit()`: Foundation on Linux has missed a
                // child's exit in production, leaving it a zombie and the
                // wait (and the scan behind it) stuck for good. Watch the
                // child here instead: reap a zombie ourselves, kill one that
                // outlives the deadline, and give up waiting soon after.
                work.enter()
                DispatchQueue.global(qos: .utility).async {
                    defer { work.leave() }
                    let deadline = Date().addingTimeInterval(timeout)
                    var killedAt: Date?
                    var zombieSince: Date?
                    while process.isRunning {
                        // Foundation normally reaps within milliseconds; only a
                        // zombie it has left for a second is ours to collect.
                        if isZombie(processID) {
                            let since = zombieSince ?? Date()
                            zombieSince = since
                            if Date().timeIntervalSince(since) > 1, let status = reap(processID) {
                                exit.record(status)
                                break
                            }
                        } else {
                            zombieSince = nil
                        }
                        if killedAt == nil, Date() >= deadline {
                            state.markTimedOut()
                            stop(process, unless: exit)
                            killedAt = Date()
                        }
                        if let killedAt, Date().timeIntervalSince(killedAt) > 5 { break }
                        usleep(50_000)
                    }
                    // The child is gone (or abandoned). A grandchild still
                    // holding the output pipe must not hold the caller too.
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
                        finish.resume(state.snapshot(exitStatus: exit.status(of: process)))
                    }
                }

                work.notify(queue: .global(qos: .utility)) {
                    finish.resume(state.snapshot(exitStatus: exit.status(of: process)))
                }
            }
        } onCancel: {
            stop(process, unless: exit)
        }
    }

    /// Signals the child unless we reaped it ourselves: Foundation still
    /// thinks it runs, and its PID may already belong to another process.
    private static func stop(_ process: Process, unless exit: ExitState) {
        guard !exit.wasReaped else { return }
        stop(process)
    }

    /// The exit status, from Foundation when it saw the exit, or from our own
    /// reap when it did not; -1 when neither (a child abandoned after a kill).
    private final class ExitState: @unchecked Sendable {
        private let lock = NSLock()
        private var reaped: Int32?

        func record(_ status: Int32) {
            lock.lock()
            reaped = status
            lock.unlock()
        }

        var wasReaped: Bool {
            lock.lock()
            defer { lock.unlock() }
            return reaped != nil
        }

        func status(of process: Process) -> Int32 {
            lock.lock()
            defer { lock.unlock() }
            if let reaped { return reaped }
            return process.isRunning ? -1 : process.terminationStatus
        }
    }

    /// Resumes a continuation exactly once, whichever path gets there first.
    private final class ResumeOnce: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Result, Never>?

        init(_ continuation: CheckedContinuation<Result, Never>) {
            self.continuation = continuation
        }

        func resume(_ result: Result) {
            lock.lock()
            let pending = continuation
            continuation = nil
            lock.unlock()
            pending?.resume(returning: result)
        }
    }

    /// Whether `pid` has exited but not been waited for.
    private static func isZombie(_ pid: Int32) -> Bool {
        guard let stat = try? String(contentsOfFile: "/proc/\(pid)/stat", encoding: .utf8),
              let close = stat.lastIndex(of: ")") else { return false }
        return stat[stat.index(after: close)...].trimmingCharacters(in: .whitespaces).hasPrefix("Z")
    }

    /// Waits for an exited `pid`, returning its exit code; nil if someone
    /// else got there first.
    private static func reap(_ pid: Int32) -> Int32? {
        var status: Int32 = 0
        guard waitpid(pid, &status, WNOHANG) == pid else { return nil }
        // WIFEXITED / WEXITSTATUS, spelled out: the C macros are not imported.
        return status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
    }

    private static func stop(_ process: Process) {
        guard process.isRunning else { return }
        let processID = process.processIdentifier
        process.terminate()
        // SIGTERM is advisory. Escalate so a hostile or wedged child cannot
        // retain its pipes and keep the request alive forever.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.25) {
            guard process.isRunning else { return }
            _ = kill(pid_t(processID), SIGKILL)
        }
    }
}
