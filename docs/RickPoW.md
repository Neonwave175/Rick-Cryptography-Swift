# Rick PoW (Swift Implementation)

* **Overview:** An Argon2-inspired hashing algorithm ported to **Swift** with **Apple Metal GPU compute shader acceleration**, designed to be computationally heavy and memory-hard.

## Swift Implementation Structure

* Core Swift source file: `cryptography/rick.swift`
* Metal GPU Compute Kernels: `cryptography/Shaders/RickShaders.metal`
* CLI Target: `executables/rick/main.swift`

## Helper Functions & Data Structures

### `BigUInt`:
* Pure Swift arbitrary-precision unsigned integer struct (`cryptography/BigUInt.swift`) supporting bitwise operations, integer square root (`isqrt`), and endian-aware byte conversions.

### `string_to_int`:
* **Input:** String, output byte length
* **Working:** Converts string to UTF-8 bytes, computes BLAKE3 hash using pure Swift `BLAKE3`, converts digest to `BigUInt` (little-endian).
* **Output:** `BigUInt`

### `array_to_int`:
* **Input:** 2D matrix array, bits per value
* **Working:** Iterates over matrix rows and elements, shifting bits into a cumulative `BigUInt`.
* **Output:** `BigUInt`

## RNG Engine

### `xoroshirosha128plus`:
* **Input:** Seed `s0` (64-bit uint or `BigUInt`)
* **Working:**
  * Uses thread-local storage (`Thread.current.threadDictionary["Rick_rngseed"]`) for thread safety during concurrent multi-threaded execution.
  * Mixes SHA-512 digest of `s0` into global/thread seed.
  * Performs 64-bit bitwise rotations (24 bits and 37 bits) and SHA-512 hashing over `s0 ^ s1`.
* **Output:** 64-bit unsigned integer

## Core Functions

### `array`:
* **Input:** String `s`, previous array number `prev`, matrix `size`
* **Working:** Converts string seed to 2D square matrix of `size x size` bytes using `xoroshirosha128plus`.

### `make_array`:
* **Input:** Memory amount `mem`, string hash `hash_str`, matrix size `matrix`, start value `stval`
* **Working:** Allocates list of matrices matching specified memory allocation budget.

### `step`:
* **Input:** Matrix list `mls`, salt `salt`, iterations `iter`, matrix size `matrix`
* **Working:** Evaluates sequential matrix steps:
  * **Tick % 4 == 1 (Matmul/Multiply Modulo)**: Computes `(h1 * h_safe) % MOD` (MOD = 2^31 - 1). Executes via Metal GPU shader `matrix_mul_mod_kernel` when GPU mode is enabled.
  * **Tick % 4 == 2 (BLAKE3 XOR Hash)**: XORs `h1` with step array, hashes via `BLAKE3`, and builds updated matrix.
  * **Tick % 4 == 3 (Branching CPU PRNG update)**: Performs bitwise arithmetic and integer square root operations to update RNG seed.
  * **Tick % 4 == 0 (XOR Modulo)**: Computes `(h1 ^ h_safe) % MOD`. Executes via Metal GPU shader `matrix_xor_mod_kernel` when GPU mode is enabled.
* **Output:** 2D `Int64` matrix result

### `rick`:
* **Input:** `v` (value), `s` (salt), `t` (time cost), `i` (iterations), `m` (memory), `ms` (matrix size), `l` (output length)
* **Working:**
  * Hashes inputs via `BLAKE3`.
  * Generates matrix array structure via `make_array`.
  * Runs sequential `step` passes for `t` rounds.
  * Converts final matrix to `BigUInt` and formats output string `$rick$<hash>:<salt>:<t>:<i>:<m>:<ms>`.
