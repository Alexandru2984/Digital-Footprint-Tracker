import Vapor

protocol FootprintPlugin: Sendable {
    var name: String { get }
    // Using Application instead of Request allows safe background execution
    func scan(input: String, on app: Application) async throws -> [PluginResult]
}

struct PluginResult: Sendable, Codable {
    let source: String
    let type: String
    let confidenceScore: Double
    let rawData: String
}
