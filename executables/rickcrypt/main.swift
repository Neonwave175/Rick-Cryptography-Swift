import Foundation
import RickCrypto

let ran = UInt64.random(in: 0...UInt64.max)
let ran2 = UInt64.random(in: 0...UInt64.max)

print("Encrypting")
var start = ProcessInfo.processInfo.systemUptime
encrypt_file("examples/Steve.jpg", "examples/Steve.rickcrypt", ran, ran2, 12345)
print(ProcessInfo.processInfo.systemUptime - start)

print("Decrypting")
start = ProcessInfo.processInfo.systemUptime
decrypt_file("examples/Steve.rickcrypt", "examples/SteveDec.jpg", ran, ran2, 12345)
print(ProcessInfo.processInfo.systemUptime - start)
