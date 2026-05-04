import Vapor

func routes(_ app: Application) throws {
    app.get { req async in
        "Digital Footprint Tracker API is running!"
    }

    // Serve OpenAPI specification
    app.get("openapi.yaml") { req throws -> Response in
        let yamlPath = Environment.get("OPENAPI_PATH")
            ?? "/home/micu/swift+vapor/frontend/openapi.yaml"
        guard FileManager.default.fileExists(atPath: yamlPath),
              let content = try? String(contentsOfFile: yamlPath, encoding: .utf8) else {
            throw Abort(.notFound)
        }
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/yaml; charset=utf-8")
        return Response(status: .ok, headers: headers, body: .init(string: content))
    }

    let scanController = ScanController()
    try app.register(collection: scanController)

    let statsController = StatsController()
    try app.register(collection: statsController)

    let authController = AuthController()
    try app.register(collection: authController)

    let userController = UserController()
    try app.register(collection: userController)

    let reportController = ReportController()
    try app.register(collection: reportController)

    let adminController = AdminController()
    try app.register(collection: adminController)

    let exportController = ExportController()
    try app.register(collection: exportController)

    let tagController = TagController()
    try app.register(collection: tagController)

    let scheduledScanController = ScheduledScanController()
    try app.register(collection: scheduledScanController)

    let correlationController = CorrelationController()
    try app.register(collection: correlationController)

    let notificationController = NotificationController()
    try app.register(collection: notificationController)

    let healthController = HealthController()
    try app.register(collection: healthController)
}
