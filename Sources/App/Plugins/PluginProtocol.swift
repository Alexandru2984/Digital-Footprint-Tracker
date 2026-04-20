import Vapor

protocol FootprintPlugin {
    var name: String { get }
    // Using Application instead of Request allows safe background execution
    func scan(input: String, on app: Application) async throws -> [PluginResult]
}

struct PluginResult {
    let source: String
    let type: String
    let confidenceScore: Double
    let rawData: String
}
