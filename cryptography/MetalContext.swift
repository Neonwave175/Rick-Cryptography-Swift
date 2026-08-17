import Foundation
import Metal

public enum RickDevice {
    case cpu
    case gpu
}

public class MetalContext {
    public static let shared = MetalContext()

    public var currentDevice: RickDevice = .cpu

    public private(set) var device: MTLDevice?
    public private(set) var commandQueue: MTLCommandQueue?
    public private(set) var library: MTLLibrary?

    public private(set) var mulModPipeline: MTLComputePipelineState?
    public private(set) var xorPipeline: MTLComputePipelineState?
    public private(set) var xorModPipeline: MTLComputePipelineState?
    public private(set) var arxStepPipeline: MTLComputePipelineState?

    private init() {
        setupMetal()
    }

    private func setupMetal() {
        guard let mtlDevice = MTLCreateSystemDefaultDevice() else {
            print("[MetalContext] Warning: Metal default device not available, fallback to CPU.")
            return
        }
        self.device = mtlDevice
        self.commandQueue = mtlDevice.makeCommandQueue()

        let shaderSource = """
        #include <metal_stdlib>
        using namespace metal;

        kernel void matrix_mul_mod_kernel(
            device int64_t* h1 [[buffer(0)]],
            constant int64_t* h_safe [[buffer(1)]],
            constant int64_t& mod [[buffer(2)]],
            uint id [[thread_position_in_grid]]
        ) {
            int64_t val = (h1[id] * h_safe[id]) % mod;
            h1[id] = val;
        }

        kernel void matrix_xor_kernel(
            device int64_t* h1 [[buffer(0)]],
            constant int64_t* h_safe [[buffer(1)]],
            uint id [[thread_position_in_grid]]
        ) {
            h1[id] = h1[id] ^ h_safe[id];
        }

        kernel void matrix_xor_mod_kernel(
            device int64_t* h1 [[buffer(0)]],
            constant int64_t* h_safe [[buffer(1)]],
            constant int64_t& mod [[buffer(2)]],
            uint id [[thread_position_in_grid]]
        ) {
            int64_t val = (h1[id] ^ h_safe[id]) % mod;
            h1[id] = val;
        }

        kernel void arx_step_kernel(
            constant uint64_t* ara [[buffer(0)]],
            constant uint64_t* arb [[buffer(1)]],
            device uint64_t* ar [[buffer(2)]],
            uint id [[thread_position_in_grid]]
        ) {
            if (id < 16) {
                uint64_t v = ar[id];
                v = (v << 24) | (v >> 40);
                v = v + arb[id];
                v = ara[id] ^ v;
                v = arb[id] ^ v;
                ar[id] = v;
            }
        }
        """

        do {
            let lib = try mtlDevice.makeLibrary(source: shaderSource, options: nil)
            self.library = lib

            if let f1 = lib.makeFunction(name: "matrix_mul_mod_kernel") {
                mulModPipeline = try mtlDevice.makeComputePipelineState(function: f1)
            }
            if let f2 = lib.makeFunction(name: "matrix_xor_kernel") {
                xorPipeline = try mtlDevice.makeComputePipelineState(function: f2)
            }
            if let f3 = lib.makeFunction(name: "matrix_xor_mod_kernel") {
                xorModPipeline = try mtlDevice.makeComputePipelineState(function: f3)
            }
            if let f4 = lib.makeFunction(name: "arx_step_kernel") {
                arxStepPipeline = try mtlDevice.makeComputePipelineState(function: f4)
            }
        } catch {
            print("[MetalContext] Error compiling Metal shaders: \(error)")
        }
    }

    public func executeMulMod(h1: inout [Int64], h_safe: [Int64], mod: Int64) {
        guard currentDevice == .gpu,
              let device = device,
              let queue = commandQueue,
              let pipeline = mulModPipeline else {
            // CPU fallback
            for i in 0..<h1.count {
                h1[i] = (h1[i] * h_safe[i]) % mod
            }
            return
        }

        let count = h1.count
        let byteCount = count * MemoryLayout<Int64>.size
        guard let bufH1 = device.makeBuffer(bytes: &h1, length: byteCount, options: .storageModeShared),
              let bufHSafe = device.makeBuffer(bytes: h_safe, length: byteCount, options: .storageModeShared) else {
            for i in 0..<h1.count {
                h1[i] = (h1[i] * h_safe[i]) % mod
            }
            return
        }

        var modVal = mod
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else { return }

        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(bufH1, offset: 0, index: 0)
        encoder.setBuffer(bufHSafe, offset: 0, index: 1)
        encoder.setBytes(&modVal, length: MemoryLayout<Int64>.size, index: 2)

        let gridSize = MTLSize(width: count, height: 1, depth: 1)
        let threadGroupSize = MTLSize(width: min(count, pipeline.maxTotalThreadsPerThreadgroup), height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
        encoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        let rawPtr = bufH1.contents().bindMemory(to: Int64.self, capacity: count)
        for i in 0..<count {
            h1[i] = rawPtr[i]
        }
    }

    public func executeXorMod(h1: inout [Int64], h_safe: [Int64], mod: Int64) {
        guard currentDevice == .gpu,
              let device = device,
              let queue = commandQueue,
              let pipeline = xorModPipeline else {
            for i in 0..<h1.count {
                h1[i] = (h1[i] ^ h_safe[i]) % mod
            }
            return
        }

        let count = h1.count
        let byteCount = count * MemoryLayout<Int64>.size
        guard let bufH1 = device.makeBuffer(bytes: &h1, length: byteCount, options: .storageModeShared),
              let bufHSafe = device.makeBuffer(bytes: h_safe, length: byteCount, options: .storageModeShared) else {
            for i in 0..<h1.count {
                h1[i] = (h1[i] ^ h_safe[i]) % mod
            }
            return
        }

        var modVal = mod
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else { return }

        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(bufH1, offset: 0, index: 0)
        encoder.setBuffer(bufHSafe, offset: 0, index: 1)
        encoder.setBytes(&modVal, length: MemoryLayout<Int64>.size, index: 2)

        let gridSize = MTLSize(width: count, height: 1, depth: 1)
        let threadGroupSize = MTLSize(width: min(count, pipeline.maxTotalThreadsPerThreadgroup), height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
        encoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        let rawPtr = bufH1.contents().bindMemory(to: Int64.self, capacity: count)
        for i in 0..<count {
            h1[i] = rawPtr[i]
        }
    }

    public func executeARXStep(ara: [UInt64], arb: [UInt64], ar: inout [UInt64]) {
        guard currentDevice == .gpu,
              let device = device,
              let queue = commandQueue,
              let pipeline = arxStepPipeline else {
            for i in 0..<16 {
                var v = ar[i]
                v = (v << 24) | (v >> 40)
                v = v &+ arb[i]
                v = ara[i] ^ v
                v = arb[i] ^ v
                ar[i] = v
            }
            return
        }

        let byteCount = 16 * MemoryLayout<UInt64>.size
        guard let bufARA = device.makeBuffer(bytes: ara, length: byteCount, options: .storageModeShared),
              let bufARB = device.makeBuffer(bytes: arb, length: byteCount, options: .storageModeShared),
              let bufAR = device.makeBuffer(bytes: &ar, length: byteCount, options: .storageModeShared) else {
            for i in 0..<16 {
                var v = ar[i]
                v = (v << 24) | (v >> 40)
                v = v &+ arb[i]
                v = ara[i] ^ v
                v = arb[i] ^ v
                ar[i] = v
            }
            return
        }

        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else { return }

        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(bufARA, offset: 0, index: 0)
        encoder.setBuffer(bufARB, offset: 0, index: 1)
        encoder.setBuffer(bufAR, offset: 0, index: 2)

        let gridSize = MTLSize(width: 16, height: 1, depth: 1)
        let threadGroupSize = MTLSize(width: 16, height: 1, depth: 1)
        encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadGroupSize)
        encoder.endEncoding()

        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        let rawPtr = bufAR.contents().bindMemory(to: UInt64.self, capacity: 16)
        for i in 0..<16 {
            ar[i] = rawPtr[i]
        }
    }
}

public func set_default_device(_ device: RickDevice) {
    MetalContext.shared.currentDevice = device
}
