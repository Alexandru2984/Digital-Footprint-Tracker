import Fluent

/// Durable ordering metadata for the SSE result stream.
///
/// `id` is an internal database identity. Clients only receive
/// `streamSequence`, which starts at one for every scan and therefore does not
/// disclose application-wide result volume.
final class ScanResultEvent: Model {
    static let schema = "scan_result_events"

    @ID(custom: "id", generatedBy: .database)
    var id: Int64?

    @Parent(key: "scan_id")
    var scan: Scan

    @Parent(key: "result_id")
    var result: Result

    @Field(key: "stream_sequence")
    var streamSequence: Int64

    init() {}
}
