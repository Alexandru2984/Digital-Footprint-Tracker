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

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let work = DispatchGroup()

                work.enter()
                DispatchQueue.global(qos: .utility).async {
                    defer {
                        try? outputPipe.fileHandleForReading.close()
                        work.leave()
                    }
                    do {
                        while let chunk = try outputPipe.fileHandleForReading.read(upToCount: 64 * 1_024),
                              !chunk.isEmpty {
                            if state.append(chunk) { stop(process) }
                        }
                    } catch {
                        state.markReadFailed()
                        stop(process)
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

                work.enter()
                DispatchQueue.global(qos: .utility).async {
                    process.waitUntilExit()
                    work.leave()
                }

                let timeoutWork = DispatchWorkItem {
                    guard process.isRunning else { return }
                    state.markTimedOut()
                    stop(process)
                }
                DispatchQueue.global(qos: .utility).asyncAfter(
                    deadline: .now() + timeout,
                    execute: timeoutWork
                )

                work.notify(queue: .global(qos: .utility)) {
                    timeoutWork.cancel()
                    continuation.resume(returning: state.snapshot(exitStatus: process.terminationStatus))
                }
            }
        } onCancel: {
            stop(process)
        }
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
