import Foundation

public struct BLAKE3 {
    private static let IV: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ]

    private static let SIGMA: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]
    ]

    private enum Flags: UInt32 {
        case chunkStart = 1
        case chunkEnd = 2
        case parent = 4
        case root = 8
        case keyedHash = 16
        case deriveKeyContext = 32
        case deriveKeyMaterial = 64
    }

    private var buffer = [UInt8]()
    private var cvStack = [[UInt32]]()
    private var key: [UInt32]
    private var flags: UInt32
    private var chunkCounter: UInt64 = 0

    public init() {
        self.key = BLAKE3.IV
        self.flags = 0
    }

    public init(key: [UInt8]) {
        precondition(key.count == 32)
        var k = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 {
            k[i] = UInt32(key[i*4]) | (UInt32(key[i*4+1]) << 8) | (UInt32(key[i*4+2]) << 16) | (UInt32(key[i*4+3]) << 24)
        }
        self.key = k
        self.flags = Flags.keyedHash.rawValue
    }

    public mutating func update(_ data: Data) {
        data.withUnsafeBytes { ptr in
            if let baseAddress = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                update(UnsafeBufferPointer(start: baseAddress, count: data.count))
            }
        }
    }

    public mutating func update(_ bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { ptr in
            update(ptr)
        }
    }

    public mutating func update(_ bufferPointer: UnsafeBufferPointer<UInt8>) {
        guard let base = bufferPointer.baseAddress else { return }
        var offset = 0
        let count = bufferPointer.count
        while offset < count {
            if buffer.count == 1024 {
                let cv = processChunk(buffer, key: key, chunkCounter: chunkCounter, flags: flags)
                pushCV(cv)
                chunkCounter += 1
                buffer.removeAll(keepingCapacity: true)
            }
            let take = min(1024 - buffer.count, count - offset)
            buffer.append(contentsOf: UnsafeBufferPointer(start: base + offset, count: take))
            offset += take
        }
    }

    private mutating func pushCV(_ cv: [UInt32]) {
        var newCV = cv
        var count = chunkCounter
        while (count & 1) != 0 {
            let left = cvStack.removeLast()
            newCV = parentCV(left: left, right: newCV, key: key, flags: flags)
            count >>= 1
        }
        cvStack.append(newCV)
    }

    public mutating func digest(length: Int = 32) -> Data {
        var outputCVStack = cvStack
        let currentChunkCounter = chunkCounter
        let currentBuffer = buffer

        if outputCVStack.isEmpty {
            // Single chunk (<= 1024 bytes)
            return compressOutput(key: key, chunkBytes: currentBuffer, chunkCounter: currentChunkCounter, flags: flags, length: length)
        } else {
            // Multi-chunk tree reduction
            var currentCV = processChunk(currentBuffer, key: key, chunkCounter: currentChunkCounter, flags: flags)

            while outputCVStack.count > 1 {
                let left = outputCVStack.removeLast()
                currentCV = parentCV(left: left, right: currentCV, key: key, flags: flags)
            }

            let left = outputCVStack.removeLast()
            let rootBlock = makeParentBlock(left: left, right: currentCV)
            return compressSqueeze(cv: key, block: rootBlock, blockLen: 64, flags: flags | Flags.parent.rawValue | Flags.root.rawValue, length: length)
        }
    }

    private func compressOutput(key: [UInt32], chunkBytes: [UInt8], chunkCounter: UInt64, flags: UInt32, length: Int) -> Data {
        let numBlocks = max(1, (chunkBytes.count + 63) / 64)
        var cv = key

        for blockIdx in 0..<(numBlocks - 1) {
            let start = blockIdx * 64
            let end = min(start + 64, chunkBytes.count)
            var block = [UInt8](repeating: 0, count: 64)
            block[0..<(end - start)] = chunkBytes[start..<end]

            var bFlags = flags
            if blockIdx == 0 { bFlags |= Flags.chunkStart.rawValue }

            let words = BLAKE3.compress(cv: cv, block: block, blockLen: UInt32(end - start), counter: chunkCounter, flags: bFlags)
            cv = Array(words[0..<8])
        }

        // Final block in the root chunk
        let lastIdx = numBlocks - 1
        let start = lastIdx * 64
        let end = min(start + 64, chunkBytes.count)
        var block = [UInt8](repeating: 0, count: 64)
        if start < chunkBytes.count {
            block[0..<(end - start)] = chunkBytes[start..<end]
        }

        var bFlags = flags | Flags.chunkEnd.rawValue | Flags.root.rawValue
        if lastIdx == 0 { bFlags |= Flags.chunkStart.rawValue }

        return compressSqueeze(cv: cv, block: block, blockLen: UInt32(end - start), flags: bFlags, length: length)
    }

    private func compressSqueeze(cv: [UInt32], block: [UInt8], blockLen: UInt32, flags: UInt32, length: Int) -> Data {
        var outData = Data()
        outData.reserveCapacity(length)
        var blockOffset: UInt64 = 0

        while outData.count < length {
            let outWords = BLAKE3.compress(cv: cv, block: block, blockLen: blockLen, counter: blockOffset, flags: flags)
            for w in outWords {
                var val = w
                for _ in 0..<4 {
                    outData.append(UInt8(val & 0xFF))
                    val >>= 8
                    if outData.count == length { break }
                }
                if outData.count == length { break }
            }
            blockOffset += 1
        }
        return outData
    }

    private func processChunk(_ bytes: [UInt8], key: [UInt32], chunkCounter: UInt64, flags: UInt32) -> [UInt32] {
        var cv = key
        let numBlocks = max(1, (bytes.count + 63) / 64)
        for blockIdx in 0..<numBlocks {
            let start = blockIdx * 64
            let end = min(start + 64, bytes.count)
            var block = [UInt8](repeating: 0, count: 64)
            if start < bytes.count {
                block[0..<(end - start)] = bytes[start..<end]
            }

            var bFlags = flags
            if blockIdx == 0 { bFlags |= Flags.chunkStart.rawValue }
            if blockIdx == numBlocks - 1 { bFlags |= Flags.chunkEnd.rawValue }

            let words = BLAKE3.compress(cv: cv, block: block, blockLen: UInt32(end - start), counter: chunkCounter, flags: bFlags)
            cv = Array(words[0..<8])
        }
        return cv
    }

    private func makeParentBlock(left: [UInt32], right: [UInt32]) -> [UInt8] {
        var block = [UInt8](repeating: 0, count: 64)
        for i in 0..<8 {
            var lw = left[i]
            var rw = right[i]
            for b in 0..<4 {
                block[i*4 + b] = UInt8(lw & 0xFF)
                lw >>= 8
                block[32 + i*4 + b] = UInt8(rw & 0xFF)
                rw >>= 8
            }
        }
        return block
    }

    private func parentCV(left: [UInt32], right: [UInt32], key: [UInt32], flags: UInt32) -> [UInt32] {
        let block = makeParentBlock(left: left, right: right)
        let words = BLAKE3.compress(cv: key, block: block, blockLen: 64, counter: 0, flags: flags | Flags.parent.rawValue)
        return Array(words[0..<8])
    }

    private static func compress(cv: [UInt32], block: [UInt8], blockLen: UInt32, counter: UInt64, flags: UInt32) -> [UInt32] {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[i*4]) | (UInt32(block[i*4+1]) << 8) | (UInt32(block[i*4+2]) << 16) | (UInt32(block[i*4+3]) << 24)
        }

        var v = [UInt32](repeating: 0, count: 16)
        v[0..<8] = cv[0..<8]
        v[8..<12] = IV[0..<4]
        v[12] = UInt32(counter & 0xFFFFFFFF)
        v[13] = UInt32(counter >> 32)
        v[14] = blockLen
        v[15] = flags

        for round in 0..<7 {
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

        var out = [UInt32](repeating: 0, count: 16)
        for i in 0..<8 {
            out[i] = v[i] ^ v[i+8]
            out[i+8] = v[i+8] ^ cv[i]
        }
        return out
    }

    private static func g(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 12)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotr(v[d] ^ v[a], 8)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 7)
    }

    private static func rotr(_ w: UInt32, _ r: UInt32) -> UInt32 {
        return (w >> r) | (w << (32 - r))
    }

    public static func hash(data: Data, length: Int = 32) -> Data {
        var b = BLAKE3()
        b.update(data)
        return b.digest(length: length)
    }

    public static func hash(bytes: [UInt8], length: Int = 32) -> Data {
        var b = BLAKE3()
        b.update(bytes)
        return b.digest(length: length)
    }
}
