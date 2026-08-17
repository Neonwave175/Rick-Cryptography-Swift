## Rick-Cryptography (Swift Port)

* **Overview:** A slow cryptography and security framework ported directly to **Swift** with **Apple Metal GPU compute shader support**.

---

### Project Structure & Organization

```
Rick-Cryptography-Swift/
├── commands/                   # Double-clickable macOS launcher scripts (.command)
│   ├── rick.command
│   ├── rickcrypt.command
│   └── rickchat.command
├── cryptography/               # Swift cryptographic library & Metal shaders
│   ├── rick.swift              # Rick PoW algorithm & matrix operations
│   ├── rickcrypt.swift        # ARX block cipher & file encryption
│   ├── rickchat.swift         # Identity key management & Ratchet KDF
│   ├── BigUInt.swift          # Pure Swift arbitrary-precision big integers
│   ├── BLAKE3.swift           # Native Swift BLAKE3 hash implementation
│   ├── BLAKE2b.swift          # Native Swift BLAKE2b hash implementation
│   ├── MetalContext.swift     # Metal GPU runtime & pipeline manager
│   └── Shaders/
│       └── RickShaders.metal  # Metal compute kernel shaders
├── executables/                # Executable CLI targets
│   ├── rick/main.swift
│   ├── rickcrypt/main.swift
│   ├── rickchat/main.swift
│   └── test/main.swift
├── keys/                       # Identity key directory (.key)
├── Package.swift               # Swift Package Manager manifest
└── setup.sh                    # Automated release build script
```

---

### RickPoW

* **Description:** An Argon2-inspired proof-of-work algorithm ported to Swift, designed to be computationally heavy and memory-hard.
* **CPU vs GPU Modes:**
  - **CPU Mode:** Runs sequential matrix computations with thread-local PRNG isolation.
  - **GPU Mode:** Accelerates heavy matrix operations (`executeMulMod`, `executeXorMod`) using Metal compute kernels (`RickShaders.metal`).
* **CLI Usage:**
  ```bash
  swift run -c release rick        # CPU Mode
  swift run -c release rick --gpu  # Metal GPU Mode
  ```
* **Documentation:** Read more in `docs/RickPoW.md`

---

### RickCrypt

* **Description:** An encryption algorithm that uses RickPoW to generate the origin matrix and ARX rounds to construct a secure keystream.
* **Mechanism:**
  - Chunks input data into 16-byte segments and XORs each segment with state-transformed matrix arrays.
  - Offloads ARX state transformations to Metal GPU compute shaders when GPU mode is enabled.
  - Thread-isolated `Rick.rngseed` ensures concurrent multi-threaded file encryption and message processing without race conditions.
* **CLI Usage:**
  ```bash
  swift run -c release rickcrypt        # CPU Mode
  swift run -c release rickcrypt --gpu  # Metal GPU Mode
  ```
* **Documentation:** Read more in `docs/RickCrypt.md`

---

### RickChat

* **Description:** A peer-to-peer UDP encrypted messaging client. Uses Curve25519 Ed25519 signatures for identity authentication, X25519 ECDH for ephemeral session agreement, a forward-secret Ratchet KDF, and RickCrypt for symmetric payload encryption.
* **Features:**
  - On-disk identity keys stored securely in the `keys/` directory.
  - Multi-threaded non-blocking UDP transport loop.
  - Fully thread-safe encryption/decryption engine supporting concurrent message receipt and delivery.
* **CLI Usage:**
  ```bash
  swift run -c release rickchat
  ```
* **Documentation:** Read more in [`/docs/RickChat.md`]

---

### Quick Start & Installation

1. **Build All Targets**:
   ```bash
   ./setup.sh
   ```

2. **Launch via Double-Clickable Scripts**:
   - `commands/rick.command`
   - `commands/rickcrypt.command`
   - `commands/rickchat.command`

---

## THIS IS NOT CONPATIBLE WITH THE PYTHON VERSION OF RICK CHAT

## License
Dual licensed under Apache 2.0 and GNU GPL v3.
