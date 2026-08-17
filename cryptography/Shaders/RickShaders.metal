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

// Metal implementation for ARX step
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
