// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RickCryptography",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "RickCrypto", targets: ["RickCrypto"]),
        .executable(name: "rick", targets: ["RickCLIRick"]),
        .executable(name: "rickcrypt", targets: ["RickCLICrypt"]),
        .executable(name: "rickchat", targets: ["RickCLIChat"]),
        .executable(name: "ricktest", targets: ["RickCLITest"])
    ],
    targets: [
        .target(
            name: "RickCrypto",
            path: "cryptography",
            resources: [
                .process("Shaders/RickShaders.metal")
            ]
        ),
        .executableTarget(
            name: "RickCLIRick",
            dependencies: ["RickCrypto"],
            path: "executables/rick"
        ),
        .executableTarget(
            name: "RickCLICrypt",
            dependencies: ["RickCrypto"],
            path: "executables/rickcrypt"
        ),
        .executableTarget(
            name: "RickCLIChat",
            dependencies: ["RickCrypto"],
            path: "executables/rickchat"
        ),
        .executableTarget(
            name: "RickCLITest",
            dependencies: ["RickCrypto"],
            path: "executables/test"
        )
    ]
)
