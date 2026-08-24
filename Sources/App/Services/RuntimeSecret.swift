import Foundation
import Vapor
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// Resolves a scalar secret from either `NAME` or `NAME_FILE`.
///
/// File-backed values are intended for systemd credentials and container
/// secrets. They are opened without following symlinks, must be private regular
/// files, and are bounded before decoding. Configuration errors fail closed and
/// never include the secret value in their description.
enum RuntimeSecret {
    static let defaultMaximumBytes = 16 * 1_024

    enum Error: Swift.Error, CustomStringConvertible, Equatable, Sendable {
        case invalidName
        case conflictingSources(String)
        case invalidPath(String)
        case unreadable(String)
        case unsafeFile(String)
        case tooLarge(String)
        case invalidValue(String)

        var description: String {
            switch self {
            case .invalidName:
                return "runtime secret name is invalid"
            case .conflictingSources(let name):
                return "configure only one of \(name) and \(name)_FILE"
            case .invalidPath(let name):
                return "\(name)_FILE must name a specific absolute path"
            case .unreadable(let name):
                return "the \(name) credential cannot be opened"
            case .unsafeFile(let name):
                return "the \(name) credential must be a private regular file"
            case .tooLarge(let name):
                return "the \(name) credential exceeds its size limit"
            case .invalidValue(let name):
                return "the \(name) credential must be a UTF-8 scalar value"
            }
        }
    }

    static func value(
        _ name: String,
        maximumBytes: Int = defaultMaximumBytes
    ) throws -> String? {
        guard validName(name), maximumBytes > 0 else { throw Error.invalidName }

        let inline = Environment.get(name)
        let rawPath = Environment.get("\(name)_FILE")?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let hasInline = inline?.isEmpty == false
        let hasFile = rawPath?.isEmpty == false
        guard !hasInline || !hasFile else { throw Error.conflictingSources(name) }
        if hasInline { return inline }
        guard hasFile, let path = rawPath else { return nil }
        guard path.hasPrefix("/"), path != "/" else { throw Error.invalidPath(name) }

        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw Error.unreadable(name) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw Error.unreadable(name) }
        // systemd's LoadCredentialEncrypted= always materializes credentials as
        // root:root 0440 plus a POSIX ACL scoped to the executing unit's user —
        // the on-disk group-read bit is inherent to that mechanism, not a leak;
        // the ACL is what actually gates access. Reject only world access.
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o007 == 0 else {
            throw Error.unsafeFile(name)
        }
        guard metadata.st_size <= maximumBytes else { throw Error.tooLarge(name) }

        let data: Data
        do {
            data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        } catch {
            throw Error.unreadable(name)
        }
        guard data.count <= maximumBytes,
              var secret = String(data: data, encoding: .utf8) else {
            throw data.count > maximumBytes ? Error.tooLarge(name) : Error.invalidValue(name)
        }
        if secret.hasSuffix("\n") {
            secret.removeLast()
            if secret.hasSuffix("\r") { secret.removeLast() }
        }
        guard !secret.contains("\n"), !secret.contains("\r"), !secret.contains("\0") else {
            throw Error.invalidValue(name)
        }
        return secret
    }

    private static func validName(_ name: String) -> Bool {
        guard !name.isEmpty, !name.hasSuffix("_FILE") else { return false }
        return name.utf8.allSatisfy { byte in
            (65...90).contains(byte) || (48...57).contains(byte) || byte == 95
        }
    }
}
