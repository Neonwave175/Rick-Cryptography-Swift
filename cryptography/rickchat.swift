import Foundation
import CryptoKit
import Network

public func h(_ parts: Data...) -> Data {
    return BLAKE2b.hash(parts: parts, digestSize: 32)
}

public func derive_rickcrypt_keys(_ password: String) -> (UInt64, UInt64, UInt64) {
    let d = BLAKE2b.hash(data: password.data(using: .utf8) ?? Data(), digestSize: 24)
    let k1 = d.subdata(in: 0..<8).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
    let k2 = d.subdata(in: 8..<16).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
    let nonce = d.subdata(in: 16..<24).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
    return (k1, k2, nonce)
}

public func serialize_crypt(_ crypt_list: [[[UInt64]]]) -> Data {
    var result = Data()
    var count = UInt32(crypt_list.count).littleEndian
    result.append(Data(bytes: &count, count: 4))

    for arr in crypt_list {
        for row in 0..<4 {
            for col in 0..<4 {
                var val = arr[row][col].littleEndian
                result.append(Data(bytes: &val, count: 8))
            }
        }
    }
    return result
}

public func deserialize_crypt(_ data_bytes: Data) -> [[[UInt64]]] {
    guard data_bytes.count >= 4 else { return [] }
    let num_chunks = data_bytes.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }

    var crypt_list = [[[UInt64]]]()
    var offset = 4
    let chunk_size = 4 * 4 * 8

    for _ in 0..<num_chunks {
        guard offset + chunk_size <= data_bytes.count else { break }
        var arr = [[UInt64]](repeating: [UInt64](repeating: 0, count: 4), count: 4)
        for i in 0..<16 {
            let val = data_bytes.subdata(in: offset + i * 8 ..< offset + (i + 1) * 8)
                .withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
            arr[i / 4][i % 4] = val
        }
        crypt_list.append(arr)
        offset += chunk_size
    }
    return crypt_list
}

public func load_or_create_identity(_ path: String, _ password: String) -> Curve25519.Signing.PrivateKey {
    let (k1, k2, nonce) = derive_rickcrypt_keys(password)
    let fileURL = URL(fileURLWithPath: path)
    let parentDir = fileURL.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)

    if FileManager.default.fileExists(atPath: path) {
        do {
            let data = try Data(contentsOf: fileURL)
            let cryptList = deserialize_crypt(data)
            let b64Str = decrypt(cryptList, k1, k2, nonce)
            if let rawData = Data(base64Encoded: b64Str) {
                return try Curve25519.Signing.PrivateKey(rawRepresentation: rawData)
            }
        } catch {
            print("[!] Failed to decrypt identity (wrong password?): \(error)")
            exit(1)
        }
    }

    print("[i] Generating new identity key...")
    let key = Curve25519.Signing.PrivateKey()
    let raw = key.rawRepresentation
    let b64Str = raw.base64EncodedString()
    let encryptedList = encrypt(b64Str, k1, k2, nonce)
    let serialized = serialize_crypt(encryptedList)
    try? serialized.write(to: fileURL)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    return key
}

public class Ratchet {
    public var chain_key: Data
    public init(chain_key: Data) {
        self.chain_key = chain_key
    }

    public func step() -> (UInt64, UInt64, UInt64) {
        let msg_key = h(chain_key, "msg".data(using: .utf8)!)
        chain_key = h(chain_key, "chain".data(using: .utf8)!)
        let k1 = msg_key.subdata(in: 0..<8).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
        let k2 = msg_key.subdata(in: 8..<16).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
        let nonce = msg_key.subdata(in: 16..<24).withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
        return (k1, k2, nonce)
    }
}

public func get_fingerprint(_ id_a: Data, _ id_b: Data) -> String {
    let sortedKeys = [id_a, id_b].sorted { $0.lexicographicallyPrecedes($1) }
    let digest = h(sortedKeys[0], sortedKeys[1], "fingerprint".data(using: .utf8)!).prefix(10)
    let hexStr = digest.map { String(format: "%02x", $0) }.joined()
    var parts = [String]()
    for i in stride(from: 0, to: hexStr.count, by: 4) {
        let start = hexStr.index(hexStr.startIndex, offsetBy: i)
        let end = hexStr.index(start, offsetBy: min(4, hexStr.count - i))
        parts.append(String(hexStr[start..<end]))
    }
    return parts.joined(separator: " ")
}
