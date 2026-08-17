# RickChat (Swift Implementation)

* **Overview:** A peer-to-peer encrypted UDP chat client. Uses **Curve25519 Ed25519** for long-term identity signing, **X25519 ECDH** for ephemeral session key exchange, a one-directional **KDF ratchet** for forward secrecy, and **RickCrypt** as the symmetric cipher for all on-disk identity storage and every chat packet.
* Messages are signed before encryption (sign-then-encrypt), so tampering or replay from a non-authenticated peer is always detectable.
* **Sources:**
  * `cryptography/rickchat.swift` — identity, ratchet, serialization
  * `executables/rickchat/main.swift` — networking, handshake, send/receive loops

---

## Constants & Packet Types (Swift)

| Constant | Value | Meaning |
|---|---|---|
| `PKT_HANDSHAKE` | `0x01` | Packet type byte for handshake |
| `PKT_CHAT` | `0x02` | Packet type byte for chat messages |
| `ED_LEN` | `32` | Ed25519 / Curve25519 public key byte length |
| `X_LEN` | `32` | X25519 ephemeral public key byte length |
| `SIG_LEN` | `64` | Ed25519 signature byte length |
| `HASH_LEN` | `32` | SHA-256 digest length (integrity check) |

**Thread Safety:** In Swift, encryption/decryption is thread-safe via the thread-local `Rick.rngseed` in `rick.swift`. No serialization executor is needed — simultaneous send and receive on separate threads works correctly.

---

## Helper Functions in `rickchat.swift`

### `h`:
* **Signature:** `func h(_ parts: Data...) -> Data`
* **Input:** Any number of `Data` byte strings
* **Working:** Feeds all parts sequentially into a single BLAKE2b hasher with a 32-byte digest size.
* **Output:** 32-byte `Data` digest

### `derive_rickcrypt_keys`:
* **Signature:** `func derive_rickcrypt_keys(_ password: String) -> (UInt64, UInt64, UInt64)`
* **Input:** Password string
* **Working:** BLAKE2b-hashes the UTF-8 password into 24 bytes, then reads three consecutive 8-byte little-endian `UInt64` values.
* **Output:** Tuple `(k1, k2, nonce)` for use as RickCrypt key material

### `serialize_crypt`:
* **Signature:** `func serialize_crypt(_ crypt_list: [[[UInt64]]]) -> Data`
* **Input:** A RickCrypt ciphertext — a list of 4×4 `[[UInt64]]` matrices
* **Working:** Writes the chunk count as a 4-byte little-endian `UInt32`, then serializes each element of every 4×4 matrix as an 8-byte little-endian `UInt64`.
* **Output:** Binary `Data` (wire/disk format for a RickCrypt ciphertext)

### `deserialize_crypt`:
* **Signature:** `func deserialize_crypt(_ data_bytes: Data) -> [[[UInt64]]]`
* **Input:** Binary `Data` from wire or disk
* **Working:** Reads the 4-byte little-endian chunk count, then walks the buffer in fixed `4 * 4 * 8`-byte slices, reconstructing each 4×4 `[[UInt64]]` matrix.
* **Output:** `[[[UInt64]]]` — a RickCrypt ciphertext list

---

## Core Cryptography & Identity

### `load_or_create_identity`:
* **Signature:** `func load_or_create_identity(_ path: String, _ password: String) -> Curve25519.Signing.PrivateKey`
* **Input:** File path to the `.key` file (under `keys/`), password string
* **Working:**
  * Derives `(k1, k2, nonce)` from the password via `derive_rickcrypt_keys`.
  * Automatically creates the parent `keys/` directory if it doesn't exist.
  * **If the file exists:** reads it, `deserialize_crypt`s the data, `decrypt`s with RickCrypt, base64-decodes the result, and reconstructs the `Curve25519.Signing.PrivateKey` from raw bytes. Exits with an error message if the password is wrong or the file is corrupted.
  * **If the file doesn't exist:** generates a fresh `Curve25519.Signing.PrivateKey`, base64-encodes its raw 32 bytes, RickCrypt-encrypts the string, serializes and writes to disk, and sets POSIX permissions to `0o600`.
* **Output:** `Curve25519.Signing.PrivateKey` (the long-term identity key)

### `Ratchet` (class):
* **Init:** `init(chain_key: Data)`
* **`step()` signature:** `func step() -> (UInt64, UInt64, UInt64)`
* **Working:**
  * Derive `msg_key = h(chain_key, "msg")`
  * Advance `chain_key = h(chain_key, "chain")`
  * Split the 24-byte `msg_key` into three consecutive little-endian `UInt64` values: `(k1, k2, nonce)`.
* **Output:** A fresh, never-reused RickCrypt key triple `(k1, k2, nonce)` for exactly one message, giving **forward secrecy** (past keys cannot be recomputed from the current chain key).

### `get_fingerprint`:
* **Signature:** `func get_fingerprint(_ id_a: Data, _ id_b: Data) -> String`
* **Input:** Two Ed25519 identity public keys as raw `Data`
* **Working:** Sorts the two keys lexicographically (so the result is identical regardless of which peer computes it), hashes them together with a `"fingerprint"` label via `h(...)`, takes the first 10 bytes, hex-encodes them, and groups into 4-character segments.
* **Output:** Human-readable "safety number" string for out-of-band MITM verification, e.g. `"a3f1 92cc 4b0d 78e1 12ab"`

---

## Networking (POSIX UDP in `main.swift`)

RickChat uses raw **POSIX BSD sockets** (`socket`, `bind`, `sendto`, `recvfrom`) from Darwin — no `Network.framework` or `asyncio` equivalent. This gives full control over the UDP transport with no framework overhead.

### `sendUDP`:
* **Signature:** `func sendUDP(sockfd: Int32, data: Data, to ip: String, port: UInt16)`
* **Working:** Constructs a `sockaddr_in`, calls `sendto` with the packet data.

### `recvUDP`:
* **Signature:** `func recvUDP(sockfd: Int32, bufferSize: Int = 65535) -> Data?`
* **Working:** Blocking `recvfrom` call. Returns `nil` if no data received.

### `sha256Digest`:
* **Signature:** `func sha256Digest(_ data: Data) -> Data`
* **Working:** Computes SHA-256 via `CryptoKit.SHA256`. Used as an explicit integrity check on each received plaintext message (in addition to the Ed25519 signature).

---

## Main Flow (`main()`)

### Setup
* Prompts for local port (default `5000`), peer IP (default `127.0.0.1`), peer port (default `5001`), optional shared pepper, and the identity password.
* Loads (or creates) the local identity via `load_or_create_identity("keys/identity_<port>.key", password)`.
* Generates a fresh ephemeral **X25519** keypair and signs the ephemeral public key with the Ed25519 identity to bind the session to the long-term identity.

### Handshake Phase
* **Packet format:** `[PKT_HANDSHAKE (1B)] [identity_pub (32B)] [eph_pub (32B)] [signature (64B)]` = 129 bytes total
* A background `Thread` (`handshakeThread`) resends the local handshake packet to the peer every second until the handshake is accepted — so neither peer has to time their launches precisely.
* On receiving a peer handshake, the Ed25519 signature over `eph_pub` is verified via `edPub.isValidSignature(r_sig, for: r_eph)`. Malformed or unsigned packets are silently dropped.

### Fingerprint Verification
* Computes the safety number via `get_fingerprint(identityPub, peerIdentityPub)` and prints it.
* Prompts the user to confirm it matches the peer's out-of-band display.
* If the user types anything other than `y`, the session is aborted and treated as a possible MITM attempt.

### Session Derivation
* **ECDH:** `Curve25519.KeyAgreement` shared secret from local ephemeral private key + peer ephemeral public key.
* **Root key:** `root = h(sharedData, sortedId[0], sortedId[1], pepperData)` — incorporates both identity keys and the optional shared pepper for additional authentication.
* **Two ratchets:**
  * `sendRatchet = Ratchet(chain_key: h(root, identityPub, "send"))`
  * `recvRatchet = Ratchet(chain_key: h(root, peerIdentityPub, "send"))`
  * Because each side uses the other's identity key to seed their receive ratchet, the two ratchets are perfectly mirrored across the connection.

### Receive Loop (Background Thread)
* Runs `recvUDP` in a tight loop on a background `Thread`.
* Re-sends the local handshake packet if a `PKT_HANDSHAKE` is received post-session (peer may have restarted).
* **In-order delivery:** buffers out-of-order `PKT_CHAT` packets in `pendingRaw: [UInt32: Data]` keyed by sequence number. Drains and decrypts in order as soon as the next expected sequence number arrives.
* **Replay protection:** packets with a sequence number below `recvSeqExpected` are dropped.
* **Decrypt path for each message:**
  1. `deserialize_crypt(rawCt)` → ciphertext matrix list
  2. `recvRatchet.step()` → `(k1, k2, nonce)` for this message slot
  3. `decrypt(cryptList, k1, k2, nonce)` → base64 string
  4. Base64-decode → `[sig (64B)] [sha256_digest (32B)] [plaintext...]`
  5. Reconstruct signed payload: `[seq_le (4B)] [peerIdentityPub (32B)] [localIdentityPub (32B)] [plaintext]`
  6. Verify Ed25519 signature via `edPub.isValidSignature(sig, for: payload)`
  7. Verify SHA-256 integrity: `sha256Digest(plaintext) == digest`
  8. Print plaintext, or print `[!! SIGNATURE INVALID]` / `[!! SHA-256 MISMATCH]` if checks fail.

### Send Loop (Main Thread)
* Reads a line of user input.
* Computes `digest = sha256Digest(msgBytes)`.
* Builds the signed payload: `[seq_le (4B)] [localIdentityPub (32B)] [peerIdentityPub (32B)] [plaintext]`
* Signs with `identity.signature(for: payload)` → 64-byte Ed25519 signature.
* Constructs the inner payload: `[sig (64B)] [digest (32B)] [plaintext]`, base64-encodes it.
* Advances `sendRatchet.step()` → `(k1, k2, nonce)`.
* `encrypt(innerStr, k1, k2, nonce)` → RickCrypt ciphertext.
* Sends UDP packet: `[PKT_CHAT (1B)] [seq_le (4B)] [serialize_crypt(encryptedList)]`

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Identity authentication** | Long-term Ed25519 keys (`Curve25519.Signing`) |
| **Session key exchange** | X25519 ECDH (`Curve25519.KeyAgreement`) |
| **Forward secrecy** | One-directional KDF ratchet (`Ratchet`) — advancing chain key can't recover past message keys |
| **MITM protection** | Safety number (`get_fingerprint`) displayed for out-of-band verification |
| **Message integrity** | Ed25519 sign-then-encrypt + SHA-256 digest check |
| **Replay protection** | Monotonically increasing sequence numbers; replays below `recvSeqExpected` are dropped |
| **On-disk key security** | Identity key files encrypted with RickCrypt, POSIX `0o600` permissions |
| **Concurrency safety** | Thread-local `Rick.rngseed` — simultaneous send/receive threads never corrupt each other's PRNG state |
