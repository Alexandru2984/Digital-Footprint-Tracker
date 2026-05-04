import Vapor

func routes(_ app: Application) throws {
    app.get { req async in
        "Digital Footprint Tracker API is running!"
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
}
