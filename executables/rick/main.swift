import Foundation
import RickCrypto

// Option to switch between CPU and GPU mode
// set_default_device(.gpu) // Uncomment or set via command line argument to test GPU mode
set_default_device(.cpu)

let startTime = ProcessInfo.processInfo.systemUptime
let result = rick("Never Gonna Give You up", "Never Gonna Let You Down", 24, 8, 4, 2, 128)
let elapsed = ProcessInfo.processInfo.systemUptime - startTime

print("[\(result.0), \(result.1)]")
print("Time", elapsed)
print("H/S = \(1.0 / elapsed)")
