// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "CCZUVPNProto",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "CCZUVPNProto",
            targets: ["CCZUVPNProto"]
        )
    ],
    targets: [
        .target(
            name: "CCZUVPNProto"
        ),
        .testTarget(
            name: "CCZUVPNProtoTests",
            dependencies: ["CCZUVPNProto"]
        )
    ]
)
