import Foundation
import RickCrypto

func runConcurrentTest() {
    let k1: UInt64 = 12345
    let k2: UInt64 = 67890
    let nonce: UInt64 = 99999

    let group = DispatchGroup()
    var successCount = 0
    let lock = NSLock()

    print("[Test] Starting 10 concurrent threads for simultaneous encrypt & decrypt...")

    for i in 0..<10 {
        group.enter()
        DispatchQueue.global().async {
            let msg = "Hello World message #\(i)"
            let encrypted = encrypt(msg, k1, k2, nonce)
            let decrypted = decrypt(encrypted, k1, k2, nonce)
            if msg == decrypted {
                lock.lock()
                successCount += 1
                lock.unlock()
            } else {
                print("Failed for thread \(i): expected '\(msg)', got '\(decrypted)'")
            }
            group.leave()
        }
    }

    group.wait()
    print("[Test] Concurrent test completed. Success count: \(successCount)/10")
}

runConcurrentTest()
