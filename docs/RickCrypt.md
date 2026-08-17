# RickCrypt (Swift Implementation)

* **Overview:** An XChaCha20-inspired encryption algorithm that uses RickPoW to generate its origin matrix and an ARX (Add-Rotate-XOR) round function to produce a secure keystream. Ported to **Swift** with optional **Metal GPU acceleration** for the ARX step.
* **Source:** `cryptography/rickcrypt.swift`

---

## Data Types

All internal state is represented as **`[[UInt64]]`** — a 4×4 Swift array of unsigned 64-bit integers. This replaces the MLX/NumPy arrays used in the original Python version.

---

## Helper Functions

### `atpos`:
* **Signature:** `func atpos(_ arr: [[UInt64]], _ x: Int, _ y: Int, _ val: UInt64) -> [[UInt64]]`
* **Input:** 4×4 matrix, row index `x`, column index `y`, value `val`
* **Working:** Returns a new copy of the matrix with the element at `[x][y]` replaced by `val`.
* **Output:** New `[[UInt64]]` matrix

### `c2a`:
* **Signature:** `func c2a(_ chunkv: [UInt8]) -> [[UInt8]]`
* **Input:** Up to 16 raw bytes
* **Working:** Fills a 4×4 `[[UInt8]]` matrix row-major with the input bytes. Any unfilled cells default to `1`.
* **Output:** 4×4 `[[UInt8]]` matrix

### `chunkify`:
* **Signatures:**
  * `func chunkify(_ b: [UInt8]) -> [[UInt8]]`
  * `func chunkify(_ s: String) -> [[UInt8]]` (UTF-8 encodes string first)
* **Working:** Splits a byte array into 16-byte chunks. The last chunk may be shorter.
* **Output:** Array of 16-byte `[UInt8]` chunks

### `chunkyarray`:
* **Signature:** `func chunkyarray(_ s: Any) -> [[[UInt8]]]`
* **Input:** A `String`, `[UInt8]`, or `Data` value
* **Working:** Calls `chunkify` to split input into 16-byte chunks, then calls `c2a` on each chunk to produce a 4×4 matrix per chunk.
* **Output:** Array of 4×4 `[[UInt8]]` matrices

---

## RNG

### `xoroshirosha128plus`:
* **Defined in:** `cryptography/rick.swift`
* **Thread Safety:** Seed is stored in **thread-local storage** via `Thread.current.threadDictionary["Rick_rngseed"]`, preventing race conditions when encrypting and decrypting simultaneously on multiple threads.
* **Working:**
  1. Set thread-local RNG seed to SHA-512 of `s0`
  2. Rotate `s0` left by 24 bits
  3. Mix `s0 ^ s1` and SHA-512 hash the result into `s1`
  4. Return `s1 + s0`
* **Why extra SHA-512:** Raw Xoroshiro128+ has known statistical weaknesses and is reversible. The SHA-512 step closes that and slows brute force.
* **Output:** `UInt64`

---

## Main Functions

### `createar`:
* **Signature:** `func createar(_ key1: UInt64, _ key2: UInt64, _ nonce: UInt64) -> [[UInt64]]`
* **Working:** Constructs the 4×4 origin matrix from `key1`, `key2`, and `nonce`:
  * `val1 = xoroshirosha128plus(nonce)`
  * `val2 = xoroshirosha128plus(nonce)` — different value because the thread-local seed advances internally
  * `val3 = UInt64(BLAKE3(rick(xoroshirosha128plus(nonce ^ key1), ...)))` — RickPoW-derived constant
  * `val4 = UInt64(BLAKE3(rick(xoroshirosha128plus(nonce ^ key2), ...)))` — same but with `key2`
  * Matrix layout:

  | C1    | C2          | C3    | C4          |
  |-------|-------------|-------|-------------|
  | key1  | key2        | key1  | key2        |
  | nonce | nonce^val3  | nonce | nonce^val4  |
  | key1  | val1        | key2  | val2        |
  | val3  | val4        | val3  | val4        |

* **Output:** `[[UInt64]]` origin matrix

### `arx`:
* **Signature:** `func arx(_ ara: [[UInt64]], _ arb: [[UInt64]], _ rev: Int) -> [[UInt64]]`
* **Working:** Runs `rev` rounds of the ARX transform:
  * **CPU path:** For each of the 16 elements:
    1. Rotate left by 24 bits
    2. Wrapping-add `arb[i]`
    3. XOR with `ara[i]`
    4. XOR with `arb[i]`
  * **GPU path:** When Metal GPU mode is active (`MetalContext.shared.currentDevice == .gpu`), dispatches the same operations to the `arx_step_kernel` Metal compute shader via `MetalContext.shared.executeARXStep`.
  * After each round, the full 16-element flat state is BLAKE3-hashed (128-byte output) and reshaped back into the 4×4 matrix.
* **Output:** Transformed `[[UInt64]]` matrix

> **Note:** This is not a textbook ARX — the interleaved BLAKE3 hash step is intentional to close the known invertibility of plain ARX.

---

## Encryption / Decryption

### `encrypt_bytes`:
* **Signature:** `func encrypt_bytes(_ b: [UInt8], _ k1: UInt64, _ k2: UInt64, _ n: UInt64, _ r: Int) -> [[[UInt64]]]`
* **Working:**
  1. Prepend and append a 16-byte random UUID prefix and suffix to the plaintext (randomized padding to prevent known-plaintext attacks on chunk boundaries).
  2. Split the padded bytes into 16-byte chunks via `chunkyarray`.
  3. Create the origin matrix with `createar(k1, k2, n)`.
  4. For each chunk: advance state with `arx(origin, prevx, r)`, then XOR each matrix element with the chunk byte.
  5. Accumulate results into the ciphertext list.
* **Output:** `[[[UInt64]]]` — list of 4×4 UInt64 ciphertext matrices

### `encrypt`:
* **Signature:** `func encrypt(_ v: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64) -> [[[UInt64]]]`
* **Working:** UTF-8 encodes the string and calls `encrypt_bytes` with `r = 1024` ARX rounds.
* **Output:** Ciphertext matrix list

### `decrypt_bytes`:
* **Signature:** `func decrypt_bytes(_ crypt: [[[UInt64]]], _ k1: UInt64, _ k2: UInt64, _ n: UInt64, _ r: Int) -> [UInt8]`
* **Working:**
  1. Recreate the same origin matrix with `createar(k1, k2, n)`.
  2. For each ciphertext matrix: advance state with `arx`, XOR to recover plaintext bytes.
  3. Strip any trailing `0x01` padding bytes.
  4. Remove the 16-byte random prefix and suffix.
* **Output:** Decrypted `[UInt8]` byte array

### `decrypt`:
* **Signature:** `func decrypt(_ crypt: [[[UInt64]]], _ k1: UInt64, _ k2: UInt64, _ n: UInt64) -> String`
* **Working:** Calls `decrypt_bytes` with `r = 1024`, then UTF-8 decodes the result.
* **Output:** Plaintext `String`

---

## File Encryption

### `encrypt_file`:
* **Signature:** `func encrypt_file(_ input_path: String, _ output_path: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64)`
* **Working:** Reads the input file as raw bytes, encrypts via `encrypt_bytes` with `r = 16` rounds, and writes the ciphertext to `output_path`. Each 4×4 matrix is serialized as 16 raw bytes (one `UInt8` per element, low byte only — suitable for binary file storage).
* **Output:** Encrypted binary file at `output_path`

### `decrypt_file`:
* **Signature:** `func decrypt_file(_ input_path: String, _ output_path: String, _ k1: UInt64, _ k2: UInt64, _ n: UInt64)`
* **Working:** Reads the encrypted binary file, reconstructs the `[[[UInt64]]]` ciphertext by reading 16-byte blocks and mapping each byte to a matrix element, then calls `decrypt_bytes` with `r = 16` and writes the result to `output_path`.
* **Output:** Decrypted file at `output_path`
