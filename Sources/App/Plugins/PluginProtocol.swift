import Vapor

protocol FootprintPlugin {
    var name: String { get }
    func scan(input: String, on req: Request) async throws -> [PluginResult]
}

struct PluginResult {
    let source: String
    let type: String
    let confidenceScore: Double
    let rawData: String
}
