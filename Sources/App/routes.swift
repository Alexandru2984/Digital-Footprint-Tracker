import Vapor

func routes(_ app: Application) throws {
    app.get { req async in
        "Digital Footprint Tracker API is running!"
    }

    // Serve OpenAPI specification
    app.get("openapi.yaml") { req throws -> Response in
        // Default resolves relative to the app's working directory instead of a
        // machine-specific absolute path; OPENAPI_PATH still overrides.
        let yamlPath = Environment.get("OPENAPI_PATH")
            ?? req.application.directory.workingDirectory + "frontend/openapi.yaml"
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

    let twoFactorController = TwoFactorController()
    try app.register(collection: twoFactorController)

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

    let identityController = IdentityController()
    try app.register(collection: identityController)

    let diffController = DiffController()
    try app.register(collection: diffController)

    let notificationController = NotificationController()
    try app.register(collection: notificationController)

    let apiKeyController = APIKeyController()
    try app.register(collection: apiKeyController)

    let healthController = HealthController()
    try app.register(collection: healthController)

    let shareController = ShareController()
    try app.register(collection: shareController)

    let bulkScanController = BulkScanController()
    try app.register(collection: bulkScanController)

    let accountController = AccountController()
    try app.register(collection: accountController)

    let investigationController = InvestigationController()
    try app.register(collection: investigationController)

    let darkWebInvestigationController = DarkWebInvestigationController()
    try app.register(collection: darkWebInvestigationController)
}
