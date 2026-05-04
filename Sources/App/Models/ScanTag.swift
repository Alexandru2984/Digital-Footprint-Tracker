import Fluent
import Vapor

final class ScanTag: Model {
    static let schema = "scan_tags"

    @ID(key: .id) var id: UUID?
    @Parent(key: "scan_id") var scan: Scan
    @Parent(key: "tag_id")  var tag: Tag

    init() {}
    init(scanID: UUID, tagID: UUID) {
        self.$scan.id = scanID
        self.$tag.id = tagID
    }
}
