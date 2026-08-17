import Foundation

public enum ByteOrder {
    case little
    case big
}

public struct BigUInt: Equatable, Comparable, CustomStringConvertible, Hashable {
    public var limbs: [UInt64]

    public init() {
        self.limbs = []
    }

    public init(_ value: UInt64) {
        if value == 0 {
            self.limbs = []
        } else {
            self.limbs = [value]
        }
    }

    /// Convenience init from a plain Int (tick counters, matrix sizes, etc.)
    public init(_ value: Int) {
        precondition(value >= 0, "BigUInt cannot represent negative values")
        self.init(UInt64(value))
    }

    public init(limbs: [UInt64]) {
        self.limbs = limbs
        self.normalize()
    }

    public init(fromBytes bytes: [UInt8], byteorder: ByteOrder = .little) {
        let b: [UInt8]
        if byteorder == .big {
            b = Array(bytes.reversed())
        } else {
            b = bytes
        }
        var limbs = [UInt64]()
        limbs.reserveCapacity((b.count + 7) / 8)
        for chunkStart in stride(from: 0, to: b.count, by: 8) {
            var val: UInt64 = 0
            let chunkEnd = min(chunkStart + 8, b.count)
            for i in 0..<(chunkEnd - chunkStart) {
                val |= UInt64(b[chunkStart + i]) << (i * 8)
            }
            limbs.append(val)
        }
        self.limbs = limbs
        self.normalize()
    }

    public mutating func normalize() {
        while let last = limbs.last, last == 0 {
            limbs.removeLast()
        }
    }

    public var isZero: Bool {
        return limbs.isEmpty
    }

    public var bitLength: Int {
        guard let last = limbs.last, !limbs.isEmpty else { return 0 }
        let highestBits = 64 - last.leadingZeroBitCount
        return (limbs.count - 1) * 64 + highestBits
    }

    public func testBit(_ n: Int) -> Bool {
        let limbIdx = n / 64
        let bitIdx = n % 64
        guard limbIdx < limbs.count else { return false }
        return (limbs[limbIdx] & (1 << bitIdx)) != 0
    }

    public mutating func setBit(_ n: Int) {
        let limbIdx = n / 64
        let bitIdx = n % 64
        while limbs.count <= limbIdx {
            limbs.append(0)
        }
        limbs[limbIdx] |= (1 << bitIdx)
        normalize()
    }

    public func toBytes(length: Int? = nil, byteorder: ByteOrder = .little) -> [UInt8] {
        var bytes = [UInt8]()
        for limb in limbs {
            var v = limb
            for _ in 0..<8 {
                bytes.append(UInt8(v & 0xFF))
                v >>= 8
            }
        }
        let naturalLen = (bitLength + 7) / 8
        if bytes.count > naturalLen {
            bytes.removeLast(bytes.count - max(naturalLen, 1))
        }
        if bytes.isEmpty {
            bytes = [0]
        }
        if let targetLen = length {
            if bytes.count < targetLen {
                bytes.append(contentsOf: [UInt8](repeating: 0, count: targetLen - bytes.count))
            } else if bytes.count > targetLen {
                bytes = Array(bytes[0..<targetLen])
            }
        }
        if byteorder == .big {
            bytes.reverse()
        }
        return bytes
    }

    public var description: String {
        if isZero { return "0" }
        var temp = self
        var digits = [Character]()
        let ten = BigUInt(10)
        while !temp.isZero {
            let (q, r) = BigUInt.divmod(temp, ten)
            let remVal = r.limbs.first ?? 0
            digits.append(Character(UnicodeScalar(UInt8(48 + remVal))))
            temp = q
        }
        return String(digits.reversed())
    }

    public static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        if lhs.limbs.count != rhs.limbs.count {
            return lhs.limbs.count < rhs.limbs.count
        }
        for i in (0..<lhs.limbs.count).reversed() {
            if lhs.limbs[i] != rhs.limbs[i] {
                return lhs.limbs[i] < rhs.limbs[i]
            }
        }
        return false
    }

    public static func == (lhs: BigUInt, rhs: BigUInt) -> Bool {
        return lhs.limbs == rhs.limbs
    }

    public static func + (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var result = [UInt64]()
        let count = max(lhs.limbs.count, rhs.limbs.count)
        var carry: UInt64 = 0
        for i in 0..<count {
            let a = i < lhs.limbs.count ? lhs.limbs[i] : 0
            let b = i < rhs.limbs.count ? rhs.limbs[i] : 0
            let (sum1, overflow1) = a.addingReportingOverflow(b)
            let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
            result.append(sum2)
            carry = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        if carry > 0 {
            result.append(carry)
        }
        return BigUInt(limbs: result)
    }

    public static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        precondition(lhs >= rhs, "Underflow in BigUInt subtraction")
        var result = [UInt64]()
        var borrow: UInt64 = 0
        for i in 0..<lhs.limbs.count {
            let a = lhs.limbs[i]
            let b = i < rhs.limbs.count ? rhs.limbs[i] : 0
            let (diff1, overflow1) = a.subtractingReportingOverflow(b)
            let (diff2, overflow2) = diff1.subtractingReportingOverflow(borrow)
            result.append(diff2)
            borrow = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        return BigUInt(limbs: result)
    }

    public static func * (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        if lhs.isZero || rhs.isZero { return BigUInt(0) }
        var result = [UInt64](repeating: 0, count: lhs.limbs.count + rhs.limbs.count)
        for i in 0..<lhs.limbs.count {
            var carry: UInt64 = 0
            for j in 0..<rhs.limbs.count {
                let product = lhs.limbs[i].multipliedFullWidth(by: rhs.limbs[j])
                let (sum1, overflow1) = result[i + j].addingReportingOverflow(product.low)
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                result[i + j] = sum2
                carry = product.high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            result[i + rhs.limbs.count] = carry
        }
        return BigUInt(limbs: result)
    }

    public static func divmod(_ dividend: BigUInt, _ divisor: BigUInt) -> (quotient: BigUInt, remainder: BigUInt) {
        precondition(!divisor.isZero, "Division by zero")
        if dividend < divisor {
            return (BigUInt(0), dividend)
        }
        if dividend == divisor {
            return (BigUInt(1), BigUInt(0))
        }
        var q = BigUInt()
        var r = BigUInt()
        let n = dividend.bitLength
        for i in (0..<n).reversed() {
            r = r << 1
            if dividend.testBit(i) {
                r.setBit(0)
            }
            if r >= divisor {
                r = r - divisor
                q.setBit(i)
            }
        }
        return (q, r)
    }

    public static func / (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        return divmod(lhs, rhs).quotient
    }

    public static func % (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        return divmod(lhs, rhs).remainder
    }

    /// Full-precision % against a small divisor, returning the remainder as
    /// UInt64. NOTE: this uses the real multi-limb divmod above — it does
    /// NOT just do `UInt64(lhs.limbs.first ?? 0) % rhs`, which would be
    /// wrong for any lhs with more than one limb.
    public static func % (lhs: BigUInt, rhs: UInt64) -> UInt64 {
        precondition(rhs != 0, "Division by zero")
        return (lhs % BigUInt(rhs)).limbs.first ?? 0
    }

    public static func ^ (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let count = max(lhs.limbs.count, rhs.limbs.count)
        var result = [UInt64]()
        for i in 0..<count {
            let a = i < lhs.limbs.count ? lhs.limbs[i] : 0
            let b = i < rhs.limbs.count ? rhs.limbs[i] : 0
            result.append(a ^ b)
        }
        return BigUInt(limbs: result)
    }

    public static func & (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let count = min(lhs.limbs.count, rhs.limbs.count)
        var result = [UInt64]()
        for i in 0..<count {
            result.append(lhs.limbs[i] & rhs.limbs[i])
        }
        return BigUInt(limbs: result)
    }

    public static func | (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let count = max(lhs.limbs.count, rhs.limbs.count)
        var result = [UInt64]()
        for i in 0..<count {
            let a = i < lhs.limbs.count ? lhs.limbs[i] : 0
            let b = i < rhs.limbs.count ? rhs.limbs[i] : 0
            result.append(a | b)
        }
        return BigUInt(limbs: result)
    }

    public static func << (lhs: BigUInt, rhs: Int) -> BigUInt {
        if lhs.isZero || rhs == 0 { return lhs }
        let limbShift = rhs / 64
        let bitShift = rhs % 64
        var result = [UInt64](repeating: 0, count: limbShift)
        var carry: UInt64 = 0
        for limb in lhs.limbs {
            if bitShift == 0 {
                result.append(limb)
            } else {
                let newLimb = (limb << bitShift) | carry
                carry = limb >> (64 - bitShift)
                result.append(newLimb)
            }
        }
        if carry > 0 {
            result.append(carry)
        }
        return BigUInt(limbs: result)
    }

    public static func >> (lhs: BigUInt, rhs: Int) -> BigUInt {
        if lhs.isZero || rhs == 0 { return lhs }
        let limbShift = rhs / 64
        let bitShift = rhs % 64
        guard limbShift < lhs.limbs.count else { return BigUInt(0) }
        var result = [UInt64]()
        let src = Array(lhs.limbs[limbShift...])
        var carry: UInt64 = 0
        for limb in src.reversed() {
            if bitShift == 0 {
                result.append(limb)
            } else {
                let newLimb = (limb >> bitShift) | carry
                carry = (limb << (64 - bitShift))
                result.append(newLimb)
            }
        }
        return BigUInt(limbs: result.reversed())
    }

    public func isqrt() -> BigUInt {
        if isZero { return BigUInt(0) }
        if self < BigUInt(4) { return BigUInt(1) }
        var x0 = BigUInt(1) << ((bitLength + 1) / 2)
        while true {
            let x1 = (x0 + (self / x0)) >> 1
            if x1 >= x0 {
                return x0
            }
            x0 = x1
        }
    }
}

extension BigUInt: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt64) {
        self.init(value)
    }
}
