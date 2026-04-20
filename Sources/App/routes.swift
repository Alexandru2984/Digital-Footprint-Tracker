import Vapor

func routes(_ app: Application) throws {
    app.get { req async in
        "Digital Footprint Tracker API is running!"
    }

    let scanController = ScanController()
    try app.register(collection: scanController)
}
