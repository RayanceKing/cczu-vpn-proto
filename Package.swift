// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "cczu-vpn-proto",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "cczu-vpn-proto",
            targets: ["cczu-vpn-proto"]
        ),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "cczu-vpn-proto"
        ),
        .testTarget(
            name: "cczu-vpn-protoTests",
            dependencies: ["cczu-vpn-proto"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
