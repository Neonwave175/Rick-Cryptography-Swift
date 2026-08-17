import Foundation

public func atpos(_ arr: [[UInt64]], _ x: Int, _ y: Int, _ val: UInt64) -> [[UInt64]] {
    var res = arr
    res[x][y] = val
    return res
}

public func createar(_ key1: UInt64, _ key2: UInt64, _ nonce: UInt64) -> [[UInt64]] {
    let val1 = xoroshirosha128plus(nonce)
    let val2 = xoroshirosha128plus(nonce)

    let arg1_v3 = String(xoroshirosha128plus(nonce ^ key1))
    let arg1_s3 = String(key1 ^ nonce)
    let rick3Res = rick(arg1_v3, arg1_s3, 12, 3, 104900, 8, 8).1
    let digest3 = BLAKE3.hash(data: String(describing: rick3Res).data(using: .utf8) ?? Data(), length: 8)
    let val3 = UInt64(BigUInt(fromBytes: Array(digest3), byteorder: .little).limbs.first ?? 0)

    let arg1_v4 = String(xoroshirosha128plus(nonce ^ key2))
    let arg1_s4 = String(key2 ^ nonce)
    let rick4Res = rick(arg1_v4, arg1_s4, 12, 3, 104900, 8, 8).1
    let digest4 = BLAKE3.hash(data: String(describing: rick4Res).data(using: .utf8) ?? Data(), length: 8)
    let val4 = UInt64(BigUInt(fromBytes: Array(digest4), byteorder: .little).limbs.first ?? 0)

    let ar: [[UInt64]] = [
        [key1, key2, key1, key2],
        [nonce, nonce ^ val3, nonce, nonce ^ val4],
        [key1, val1, key2, val2],
        [val3, val4, val3, val4]
    ]
    return ar
}

public func arx(_ ara: [[UInt64]], _ arb: [[UInt64]], _ rev: Int) -> [[UInt64]] {
    var ar = ara
    let flatAra = ara.flatMap { $0 }
    let flatArb = arb.flatMap { $0 }

    for _ in 0..<rev {
        var flatAr = ar.flatMap { $0 }
        if MetalContext.shared.currentDevice == .gpu {
            MetalContext.shared.executeARXStep(ara: flatAra, arb: flatArb, ar: &flatAr)
        } else {
            for i in 0..<16 {
                var v = flatAr[i]
                v = (v << 24) | (v >> 40)
                v = v &+ flatArb[i]
                v = flatAra[i] ^ v
                v = flatArb[i] ^ v
                flatAr[i] = v
            }
        }

        // --- batched hash step ---
        var data = Data()
        data.reserveCapacity(128)
        for i in 0..<16 {
            var v = flatAr[i].littleEndian
            withUnsafeBytes(of: &v) { ptr in
                data.append(contentsOf: ptr)
            }
        }

        let digest = BLAKE3.hash(data: data, length: 128)
        let digestBytes = Array(digest)

        var newFlat = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            var val: UInt64 = 0
            for b in 0..<8 {
                val |= UInt64(digestBytes[i * 8 + b]) << (b * 8)
            }
            newFlat[i] = val
        }

        for r in 0..<4 {
            for c in 0..<4 {
                ar[r][c] = newFlat[r * 4 + c]
            }
        }
    }
    return ar
}

public func c2a(_ chunkv: [UInt8]) -> [[UInt8]] {
    var chunka = [[UInt8]](repeating: [UInt8](repeating: 1, count: 4), count: 4)
    for (tick, chunk) in chunkv.enumerated() {
        if tick < 16 {
            chunka[tick / 4][tick % 4] = chunk
        }
    }
    return chunka
}

public func chunkify(_ b: [UInt8]) -> [[UInt8]] {
    var chunks = [[UInt8]]()
    for i in stride(from: 0, to: b.count, by: 16) {
        let end = min(i + 16, b.count)
        chunks.append(Array(b[i..<end]))
    }
    return chunks
}

public func chunkify(_ s: String) -> [[UInt8]] {
    return chunkify(Array(s.utf8))
}

public func chunkyarray(_ s: Any) -> [[[UInt8]]] {
    let chunks: [[UInt8]]
    if let str = s as? String {
        chunks = chunkify(str)
    } else if let bytes = s as? [UInt8] {
        chunks = chunkify(bytes)
    } else if let data = s as? Data {
        chunks = chunkify(Array(data))
    } else {
        chunks = []
    }

    var arrays = [[[UInt8]]]()
    for chunk in chunks {
        arrays.append(c2a(chunk))
    }
    return arrays
}

public func encrypt_bytes(_ b: [UInt8], _ k1: UInt64, _ k2: UInt64, _ n: UInt64, _ r: Int) -> [[[UInt64]]] {
    Rick.rngseed = 0
    let randomPrefix = Array(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).utf8)
    let randomSuffix = Array(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).utf8)

    var val_bytes = [UInt8]()
    val_bytes.append(contentsOf: randomPrefix)
    val_bytes.append(contentsOf: b)
    val_bytes.append(contentsOf: randomSuffix)

    let arrayls = chunkyarray(val_bytes)
    var crypt = [[[UInt64]]]()
    var origin = createar(k1, k2, n)
    let prevx = origin

    for array in arrayls {
        origin = arx(origin, prevx, r)
        var newit = [[UInt64]](repeating: [UInt64](repeating: 0, count: 4), count: 4)
        for row in 0..<4 {
            for col in 0..<4 {
                newit[row][col] = UInt64(array[row][col]) ^ origin[row][col]
            }
        }
        crypt.append(newit)
    }
    return crypt
}

public func encrypt(_ v: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64) -> [[[UInt64]]] {
    return encrypt_bytes(Array(v.utf8), k1, k2, n, 1024)
}

public func decrypt_bytes(_ crypt: [[[UInt64]]], _ k1: UInt64, _ k2: UInt64, _ n: UInt64, _ r: Int) -> [UInt8] {
    Rick.rngseed = 0
    var origin = createar(k1, k2, n)
    let prevx = origin
    var decrypted_bytes = [UInt8]()

    for array in crypt {
        origin = arx(origin, prevx, r)
        for row in 0..<4 {
            for col in 0..<4 {
                let xored = array[row][col] ^ origin[row][col]
                decrypted_bytes.append(UInt8(xored & 0xFF))
            }
        }
    }

    // Strip trailing 0x01 padding bytes
    while let last = decrypted_bytes.last, last == 1 {
        decrypted_bytes.removeLast()
    }

    if decrypted_bytes.count > 32 {
        return Array(decrypted_bytes[16..<(decrypted_bytes.count - 16)])
    }
    return decrypted_bytes
}

public func decrypt(_ crypt: [[[UInt64]]], _ k1: UInt64, _ k2: UInt64, _ n: UInt64) -> String {
    let bytes = decrypt_bytes(crypt, k1, k2, n, 1024)
    return String(bytes: bytes, encoding: .utf8) ?? ""
}

public func encrypt_file(_ input_path: String, _ output_path: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64) {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: input_path)) else { return }
    let crypt = encrypt_bytes(Array(data), k1, k2, n, 16)
    var outData = Data()
    for array in crypt {
        for row in 0..<4 {
            for col in 0..<4 {
                outData.append(UInt8(array[row][col] & 0xFF))
            }
        }
    }
    try? outData.write(to: URL(fileURLWithPath: output_path))
}

public func decrypt_file(_ input_path: String, _ output_path: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64) {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: input_path)) else { return }
    var crypt = [[[UInt64]]]()
    var offset = 0
    let count = data.count
    while offset + 16 <= count {
        var mat = [[UInt64]](repeating: [UInt64](repeating: 0, count: 4), count: 4)
        for i in 0..<16 {
            mat[i / 4][i % 4] = UInt64(data[offset + i])
        }
        crypt.append(mat)
        offset += 16
    }
    let decrypted = decrypt_bytes(crypt, k1, k2, n, 16)
    try? Data(decrypted).write(to: URL(fileURLWithPath: output_path))
}
