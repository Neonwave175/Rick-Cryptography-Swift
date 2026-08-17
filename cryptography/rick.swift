import Foundation
import CryptoKit

// =====================================================================
// Rick Cryptography Implementation
// Note: Core BigUInt definition, ByteOrder enum, limbs, bitLength,
// toBytes, fromBytes, and isqrt are sourced from BigUInt.swift.
// =====================================================================

public struct Rick {
    public static var rngseed: BigUInt {
        get {
            return (Thread.current.threadDictionary["Rick_rngseed"] as? BigUInt) ?? BigUInt(1)
        }
        set {
            Thread.current.threadDictionary["Rick_rngseed"] = newValue
        }
    }
}

private let MASK64 = BigUInt(UInt64.max)

private func sha512Low8(_ value: BigUInt) -> BigUInt {
    let masked = value & MASK64
    let bytes8 = masked.toBytes(length: 8, byteorder: .little)
    let digest = SHA512.hash(data: Data(bytes8))
    return BigUInt(fromBytes: Array(digest.prefix(8)), byteorder: .little)
}

/// Full-precision port of Python's xoroshirosha128plus(s0).
public func xoroshirosha128plus(_ s0In: BigUInt) -> BigUInt {
    var s0 = s0In
    Rick.rngseed = Rick.rngseed ^ sha512Low8(s0)
    if Rick.rngseed.isZero {
        Rick.rngseed = BigUInt(1)
    }
    var s1 = Rick.rngseed
    Rick.rngseed = (s0 + s1) & MASK64
    s1 = s1 ^ s0
    let s0_rot = ((s0 << 24) | (s0 >> 40)) & MASK64
    s0 = (s0_rot ^ s1 ^ (s1 << 16)) & MASK64
    s1 = ((s1 << 37) | (s1 >> 27)) & MASK64
    s1 = sha512Low8(s0 ^ s1) & MASK64
    let result = (s0 + s1) & MASK64
    return result
}

public func xoroshirosha128plus(_ s0: UInt64) -> UInt64 {
    return xoroshirosha128plus(BigUInt(s0)).limbs.first ?? 0
}

public func string_to_int(_ s: String, n_bytes: Int = 8) -> BigUInt {
    let digest = BLAKE3.hash(data: s.data(using: .utf8) ?? Data(), length: n_bytes)
    return BigUInt(fromBytes: Array(digest), byteorder: .little)
}

public func array_to_int(_ arr: [[UInt8]], bits_per_value: Int = 64) -> BigUInt {
    var result = BigUInt(0)
    for row in arr {
        for v in row {
            result = (result << bits_per_value) | BigUInt(UInt64(v))
        }
    }
    return result
}

public func array_to_int(_ arr: [[Int64]], bits_per_value: Int = 64) -> BigUInt {
    var result = BigUInt(0)
    for row in arr {
        for v in row {
            result = (result << bits_per_value) | BigUInt(UInt64(bitPattern: v))
        }
    }
    return result
}

public func array(_ s: String, _ prev: BigUInt, _ size: Int) -> [[UInt8]] {
    let n_cells = size * size
    let b = Array(s.utf8)
    var seed_val = BigUInt(0)
    for byte_val in b {
        seed_val = ((seed_val << 8) | BigUInt(UInt64(byte_val))) & MASK64
    }
    var s0 = seed_val
    var values = [UInt8]()
    values.reserveCapacity(n_cells)
    while values.count < n_cells {
        let result = xoroshirosha128plus(s0)
        Rick.rngseed = xoroshirosha128plus(prev)
        s0 = result
        let resultU64 = result.limbs.first ?? 0
        for i in 0..<8 {
            if values.count >= n_cells { break }
            values.append(UInt8((resultU64 >> (8 * i)) & 0xFF))
        }
    }
    var matrix = [[UInt8]](repeating: [UInt8](repeating: 0, count: size), count: size)
    for r in 0..<size {
        for c in 0..<size {
            matrix[r][c] = values[r * size + c]
        }
    }
    return matrix
}

public func make_array(_ mem: Int, _ hash_str: String, _ matrix: Int, _ stval: BigUInt) -> [[[UInt8]]] {
    let bytes_per_array = matrix * matrix
    let mn = mem / bytes_per_array

    var mlist = [[[UInt8]]]()
    for i in 0..<mn {
        if mlist.isEmpty {
            let arr = array(hash_str, xoroshirosha128plus(stval), matrix)
            Rick.rngseed = array_to_int(arr)
            mlist.append(arr)
        } else {
            let prevIdx = Int((xoroshirosha128plus(Rick.rngseed)) % UInt64(mlist.count))
            let prev_val = array_to_int(mlist[prevIdx])
            let arr = array(hash_str, prev_val, matrix)
            let idx2 = Int((xoroshirosha128plus(BigUInt(i))) % UInt64(mlist.count))
            Rick.rngseed = array_to_int(mlist[idx2])
            mlist.append(arr)
        }
    }
    return mlist
}

public func step(_ mls: [[[UInt8]]], _ salt: BigUInt, _ iter: Int, _ matrix: Int) -> [[Int64]] {
    var hlist = [[[UInt8]]]()
    for _ in 0..<(iter * 8) {
        let idx = Int((xoroshirosha128plus(salt)) % UInt64(mls.count))
        hlist.append(mls[idx])
        Rick.rngseed = xoroshirosha128plus(array_to_int(mls[idx]))
    }

    let MOD: Int64 = 2147483647
    var h1 = [[Int64]](repeating: [Int64](repeating: 1, count: matrix), count: matrix)
    var tick = 0

    for hOriginal in hlist {
        tick += 1
        var h_safe = [[Int64]](repeating: [Int64](repeating: 0, count: matrix), count: matrix)
        for r in 0..<matrix {
            for c in 0..<matrix {
                h_safe[r][c] = Int64(hOriginal[r][c]) + 1
            }
        }

        var hWide = [[Int64]](repeating: [Int64](repeating: 0, count: matrix), count: matrix)
        for r in 0..<matrix {
            for c in 0..<matrix {
                hWide[r][c] = Int64(hOriginal[r][c])
            }
        }

        let mode = tick % 4
        if mode == 1 {
            for r in 0..<matrix {
                for c in 0..<matrix {
                    h1[r][c] = (h1[r][c] * h_safe[r][c]) % MOD
                }
            }
        } else if mode == 2 {
            for r in 0..<matrix {
                for c in 0..<matrix {
                    hWide[r][c] = h1[r][c] ^ hWide[r][c]
                }
            }
            let arint = array_to_int(hWide)
            let num_bytes = max(1, (arint.bitLength + 7) / 8)
            let h_bytes = arint.toBytes(length: num_bytes, byteorder: .little)
            let digest = BLAKE3.hash(bytes: h_bytes, length: matrix * matrix * 8)
            let digestStr = String(decoding: digest, as: UTF8.self)
            let newH1Bytes = array(digestStr, xoroshirosha128plus(BigUInt(tick)), matrix)
            for r in 0..<matrix {
                for c in 0..<matrix {
                    h1[r][c] = Int64(newH1Bytes[r][c])
                }
            }
        } else if mode == 3 {
            var arint = array_to_int(hOriginal)
            let divisor = xoroshirosha128plus(arint)
            arint = divisor.isZero ? arint : arint % divisor
            let check1 = xoroshirosha128plus(arint).limbs.first ?? 0
            let modTick = UInt64(tick % 4)
            if modTick != 0 && check1 % modTick == 1 {
                Rick.rngseed = xoroshirosha128plus(arint)
                if tick != 0 && (Rick.rngseed % UInt64(tick)) == 1 {
                    for _ in 0..<(tick % 128) {
                        Rick.rngseed = xoroshirosha128plus(arint)
                        arint = xoroshirosha128plus(arint)
                        if Rick.rngseed >= xoroshirosha128plus(arint) {
                            Rick.rngseed = xoroshirosha128plus(arint)
                            arint = xoroshirosha128plus(arint)
                        }
                    }
                }
            } else if modTick != 0 && check1 % modTick == 2 {
                Rick.rngseed = xoroshirosha128plus(arint * arint)
            } else {
                Rick.rngseed = xoroshirosha128plus((arint * arint * arint).isqrt())
            }
        } else {
            for r in 0..<matrix {
                for c in 0..<matrix {
                    h1[r][c] = (h1[r][c] ^ h_safe[r][c]) % MOD
                }
            }
        }

        Rick.rngseed = xoroshirosha128plus(array_to_int(hWide))
    }

    return h1
}

public func rick(_ v: String, _ s: String, _ t: Int, _ i: Int, _ m: Int, _ ms: Int, _ l: Int) -> (String, BigUInt) {
    var h = BLAKE3()
    h.update(v.data(using: .utf8) ?? Data())
    h.update(s.data(using: .utf8) ?? Data())

    var tInt = Int64(t).littleEndian
    var iInt = Int64(i).littleEndian
    var mInt = Int64(m).littleEndian
    var msInt = Int64(ms).littleEndian
    h.update(Data(bytes: &tInt, count: 8))
    h.update(Data(bytes: &iInt, count: 8))
    h.update(Data(bytes: &mInt, count: 8))
    h.update(Data(bytes: &msInt, count: 8))

    let digest = h.digest()
    let digestBig = BigUInt(fromBytes: Array(digest), byteorder: .little)
    Rick.rngseed = digestBig

    let salt = s
    let sVal = string_to_int(s)

    var ar = make_array(m, v, ms, digestBig)

    for _ in 0..<t {
        let idx = Int((xoroshirosha128plus(sVal)) % UInt64(ar.count))
        let stepRes = step(ar, sVal, i, ms)
        var uint8Mat = [[UInt8]](repeating: [UInt8](repeating: 0, count: ms), count: ms)
        for r in 0..<ms {
            for c in 0..<ms {
                uint8Mat[r][c] = UInt8(stepRes[r][c] & 0xFF)
            }
        }
        ar[idx] = uint8Mat
        let idx2 = Int((xoroshirosha128plus(sVal)) % UInt64(ar.count))
        Rick.rngseed = xoroshirosha128plus(array_to_int(ar[idx2]))
    }

    let finalStepRes = step(ar, sVal, ar.count, ms)
    let resultBig = array_to_int(finalStepRes)
    let byte_length = max(1, (resultBig.bitLength + 7) / 8)
    var resultb = resultBig.toBytes(length: byte_length, byteorder: .little)
    if resultb.count > l {
        resultb = Array(resultb[0..<l])
    }
    let finalResult = BigUInt(fromBytes: resultb, byteorder: .big)
    let resString = "$rick$\(finalResult):\(salt):\(t):\(i):\(m):\(ms)"
    return (resString, finalResult)
}
