// swift-tools-version: 5.7.1
import PackageDescription

let package = Package(
    name: "ExampleSigner",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "ExampleSigner",
            targets: ["ExampleSigner"]),
    ],
    dependencies: [
        .package(url: "https://github.com/BlockchainCommons/BCSwiftFoundation.git", from: "6.0.0"),
        .package(url: "https://github.com/WolfMcNally/WolfBase.git", from: "5.0.0")
    ],
    targets: [
        .target(
            name: "ExampleSigner",
            dependencies: [
                "WolfBase",
                .product(name: "BCFoundation", package: "BCSwiftfoundation")
            ]),
        .testTarget(
            name: "ExampleSignerTests",
            dependencies: ["ExampleSigner"]),
    ]
)
