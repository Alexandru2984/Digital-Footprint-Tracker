import Vapor

func routes(_ app: Application) throws {
    app.get { req async in
        "Digital Footprint Tracker API is running!"
    }

    let scanController = ScanController()
    try app.register(collection: scanController)

    let statsController = StatsController()
    try app.register(collection: statsController)
}
