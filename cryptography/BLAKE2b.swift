import Foundation

public struct BLAKE2b {
    private static let IV: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527ade682d1d, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]

    private static let SIGMA: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
    ]

    public static func hash(parts: [Data], digestSize: Int = 32) -> Data {
        var totalData = Data()
        for p in parts {
            totalData.append(p)
        }
        return hash(data: totalData, digestSize: digestSize)
    }

    public static func hash(data: Data, digestSize: Int = 32) -> Data {
        precondition(digestSize >= 1 && digestSize <= 64)
        var h = IV
        h[0] ^= 0x01010000 | UInt64(digestSize)

        var bytes = [UInt8](data)
        var offset = 0
        var bytesCompressed: UInt64 = 0

        if bytes.isEmpty {
            bytes = [UInt8](repeating: 0, count: 128)
            compress(&h, block: bytes, bytesCompressed: 0, isLast: true)
        } else {
            while offset < bytes.count {
                let remaining = bytes.count - offset
                let take = min(128, remaining)
                var block = [UInt8](repeating: 0, count: 128)
                block[0..<take] = bytes[offset..<(offset + take)]

                bytesCompressed += UInt64(take)
                let isLast = (offset + take == bytes.count)
                compress(&h, block: block, bytesCompressed: bytesCompressed, isLast: isLast)
                offset += take
            }
        }

        var outData = Data()
        for w in h {
            var val = w
            for _ in 0..<8 {
                outData.append(UInt8(val & 0xFF))
                val >>= 8
                if outData.count == digestSize { break }
            }
            if outData.count == digestSize { break }
        }
        return outData
    }

    private static func compress(_ h: inout [UInt64], block: [UInt8], bytesCompressed: UInt64, isLast: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt64(block[i*8]) | (UInt64(block[i*8+1]) << 8) | (UInt64(block[i*8+2]) << 16) | (UInt64(block[i*8+3]) << 24) |
                   (UInt64(block[i*8+4]) << 32) | (UInt64(block[i*8+5]) << 40) | (UInt64(block[i*8+6]) << 48) | (UInt64(block[i*8+7]) << 56)
        }

        var v = [UInt64](repeating: 0, count: 16)
        v[0..<8] = h[0..<8]
        v[8..<16] = IV[0..<8]
        v[12] ^= bytesCompressed
        v[13] ^= 0 // upper 64 bits of length if needed
        if isLast {
            v[14] = ~v[14]
        }

        for round in 0..<12 {
            let s = SIGMA[round]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i+8]
        }
    }

    private static func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 63)
    }

    private static func rotr(_ w: UInt64, _ r: UInt64) -> UInt64 {
        return (w >> r) | (w << (64 - r))
    }
}
