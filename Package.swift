// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "AppStoreConnector",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(
            name: "AppStoreConnector",
            targets: ["AppStoreConnector"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "AppStoreConnector",
            dependencies: []
        ),
        .testTarget(
            name: "AppStoreConnectorTests",
            dependencies: ["AppStoreConnector"]
        ),
        .testTarget(
            name: "AppStoreConnectorIntegrationTests",
            dependencies: ["AppStoreConnector"]
        ),
    ]
)
