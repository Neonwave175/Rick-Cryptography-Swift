import Foundation
import CryptoKit
import RickCrypto
import Darwin

let PKT_HANDSHAKE: UInt8 = 0x01
let PKT_CHAT: UInt8 = 0x02
let ED_LEN = 32
let X_LEN = 32
let SIG_LEN = 64
let HASH_LEN = 32  // SHA-256 digest length

func getLine(_ prompt: String, defaultVal: String = "") -> String {
    print(prompt, terminator: "")
    fflush(stdout)
    if let line = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines), !line.isEmpty {
        return line
    }
    return defaultVal
}

func sendUDP(sockfd: Int32, data: Data, to ip: String, port: UInt16) {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    inet_pton(AF_INET, ip, &addr.sin_addr)

    data.withUnsafeBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        withUnsafePointer(to: &addr) { saPtr in
            saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                _ = sendto(sockfd, base, data.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
}

func recvUDP(sockfd: Int32, bufferSize: Int = 65535) -> Data? {
    var buf = [UInt8](repeating: 0, count: bufferSize)
    var clientAddr = sockaddr_in()
    var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
    let n = withUnsafeMutablePointer(to: &clientAddr) { saPtr in
        saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
            recvfrom(sockfd, &buf, bufferSize, 0, sockaddrPtr, &addrLen)
        }
    }
    if n > 0 {
        return Data(buf[0..<n])
    }
    return nil
}

/// SHA-256 digest of arbitrary data, as raw bytes.
func sha256Digest(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

func main() {
    print("--- Secure P2P Chat Setup ---")
    let localPortStr = getLine("Local Port [default 5000]: ", defaultVal: "5000")
    let localPort = UInt16(localPortStr) ?? 5000
    let peerIP = getLine("Peer IP [default 127.0.0.1]: ", defaultVal: "127.0.0.1")
    let peerPortStr = getLine("Peer Port [default 5001]: ", defaultVal: "5001")
    let peerPort = UInt16(peerPortStr) ?? 5001
    let pepper = getLine("Optional extra shared pepper (blank is fine): ")

    print("Local Identity Password: ", terminator: "")
    fflush(stdout)
    let disk_pw = readLine() ?? ""

    let identityPath = "keys/identity_\(localPort).key"
    let identity = load_or_create_identity(identityPath, disk_pw)
    let identityPub = identity.publicKey.rawRepresentation
    let identityPubHex = identityPub.map { String(format: "%02x", $0) }.joined()
    print("[i] Identity active: \(identityPubHex.prefix(16))...")

    let ephPriv = Curve25519.KeyAgreement.PrivateKey()
    let ephPub = ephPriv.publicKey.rawRepresentation
    guard let ephSig = try? identity.signature(for: ephPub) else {
        print("[!] Failed to sign ephemeral key")
        return
    }

    // Setup UDP Socket
    let sockfd = socket(AF_INET, SOCK_DGRAM, 0)
    guard sockfd >= 0 else {
        print("[!] Failed to create UDP socket")
        return
    }

    var reuse: Int32 = 1
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var bindAddr = sockaddr_in()
    bindAddr.sin_family = sa_family_t(AF_INET)
    bindAddr.sin_port = localPort.bigEndian
    bindAddr.sin_addr.s_addr = INADDR_ANY.bigEndian

    let bindRes = withUnsafePointer(to: &bindAddr) { saPtr in
        saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
            bind(sockfd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }

    guard bindRes == 0 else {
        print("[!] Failed to bind UDP socket to port \(localPort)")
        return
    }

    // Prepare Handshake Packet
    var handshakePkt = Data([PKT_HANDSHAKE])
    handshakePkt.append(identityPub)
    handshakePkt.append(ephPub)
    handshakePkt.append(ephSig)

    class AtomicFlag {
        var value = false
        let lock = NSLock()
        func set(_ v: Bool) {
            lock.lock()
            value = v
            lock.unlock()
        }
        func get() -> Bool {
            lock.lock()
            let v = value
            lock.unlock()
            return v
        }
    }

    let handshakeFlag = AtomicFlag()

    // Background Handshake Sender
    let handshakeThread = Thread {
        while !handshakeFlag.get() {
            sendUDP(sockfd: sockfd, data: handshakePkt, to: peerIP, port: peerPort)
            Thread.sleep(forTimeInterval: 1.0)
        }
    }
    handshakeThread.start()

    print("[+] Waiting for peer handshake...")
    var peerIdentityPub: Data?
    var peerEphPub: Data?

    // Handshake Receive Loop
    while peerIdentityPub == nil {
        guard let pkt = recvUDP(sockfd: sockfd) else { continue }
        if pkt.count == 1 + ED_LEN + X_LEN + SIG_LEN && pkt[0] == PKT_HANDSHAKE {
            let body = pkt.subdata(in: 1..<pkt.count)
            let r_id = body.subdata(in: 0..<ED_LEN)
            let r_eph = body.subdata(in: ED_LEN..<ED_LEN + X_LEN)
            let r_sig = body.subdata(in: ED_LEN + X_LEN..<ED_LEN + X_LEN + SIG_LEN)

            if let edPub = try? Curve25519.Signing.PublicKey(rawRepresentation: r_id) {
                if edPub.isValidSignature(r_sig, for: r_eph) {
                    peerIdentityPub = r_id
                    peerEphPub = r_eph
                }
            }
        }
    }

    guard let pIdPub = peerIdentityPub, let pEphPub = peerEphPub else { return }

    let fp = get_fingerprint(identityPub, pIdPub)
    print("\n" + String(repeating: "=", count: 60))
    print("  SAFETY NUMBER -- verify this OUT OF BAND before trusting:")
    print("\n      \(fp)\n")
    print(String(repeating: "=", count: 60))

    let accept = getLine("Does this match your peer? [y/N]: ").lowercased()
    if accept != "y" {
        print("[!] Aborting. Treat this as a possible MITM.")
        handshakeFlag.set(true)
        return
    }

    handshakeFlag.set(true)

    // Session Derivation
    guard let peerXPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pEphPub),
          let sharedSecret = try? ephPriv.sharedSecretFromKeyAgreement(with: peerXPub) else {
        print("[!] Key agreement failed.")
        return
    }

    let sharedData = sharedSecret.withUnsafeBytes { Data($0) }
    let sortedId = [identityPub, pIdPub].sorted { $0.lexicographicallyPrecedes($1) }
    let root = h(sharedData, sortedId[0], sortedId[1], pepper.data(using: .utf8) ?? Data())

    let sendRatchet = Ratchet(chain_key: h(root, identityPub, "send".data(using: .utf8)!))
    let recvRatchet = Ratchet(chain_key: h(root, pIdPub, "send".data(using: .utf8)!))

    print("[+] Verified. Forward-secret session established.\n")

    let stateLock = NSLock()
    var sendSeq: UInt32 = 0
    var recvSeqExpected: UInt32 = 0
    var pendingRaw = [UInt32: Data]()

    // Background Receive Loop
    let recvThread = Thread {
        while true {
            guard let data = recvUDP(sockfd: sockfd) else { continue }
            if data.isEmpty { continue }

            if data[0] == PKT_HANDSHAKE {
                sendUDP(sockfd: sockfd, data: handshakePkt, to: peerIP, port: peerPort)
                continue
            }

            if data[0] != PKT_CHAT || data.count < 5 {
                continue
            }

            let seq = data.subdata(in: 1..<5).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            let ctBody = data.subdata(in: 5..<data.count)

            stateLock.lock()
            if seq < recvSeqExpected {
                stateLock.unlock()
                continue
            }
            pendingRaw[seq] = ctBody

            while let rawCt = pendingRaw.removeValue(forKey: recvSeqExpected) {
                let currentSeq = recvSeqExpected
                recvSeqExpected += 1
                stateLock.unlock()

                let cryptList = deserialize_crypt(rawCt)
                let (k1, k2, nonce) = recvRatchet.step()
                let innerStr = decrypt(cryptList, k1, k2, nonce)

                // Layout: [sig (64)] [sha256 digest (32)] [plaintext...]
                if let innerBytes = Data(base64Encoded: innerStr), innerBytes.count >= SIG_LEN + HASH_LEN {
                    let sig = innerBytes.subdata(in: 0..<SIG_LEN)
                    let digest = innerBytes.subdata(in: SIG_LEN..<SIG_LEN + HASH_LEN)
                    let plaintext = innerBytes.subdata(in: (SIG_LEN + HASH_LEN)..<innerBytes.count)

                    var payload = Data()
                    var seqLE = currentSeq.littleEndian
                    payload.append(Data(bytes: &seqLE, count: 4))
                    payload.append(pIdPub)
                    payload.append(identityPub)
                    payload.append(plaintext)

                    if let edPub = try? Curve25519.Signing.PublicKey(rawRepresentation: pIdPub),
                       edPub.isValidSignature(sig, for: payload) {
                        // Signature already proves integrity; SHA-256 is an extra explicit check.
                        if sha256Digest(plaintext) == digest {
                            let text = String(data: plaintext, encoding: .utf8) ?? "[Binary Data]"
                            print("\rPeer: \(text)\n> ", terminator: "")
                            fflush(stdout)
                        } else {
                            print("\rPeer: [!! SHA-256 MISMATCH -- message corrupted or tampered !!]\n> ", terminator: "")
                            fflush(stdout)
                        }
                    } else {
                        print("\rPeer: [!! SIGNATURE INVALID -- dropped message !!]\n> ", terminator: "")
                        fflush(stdout)
                    }
                } else {
                    print("\rPeer: [Decryption Failed]\n> ", terminator: "")
                    fflush(stdout)
                }

                stateLock.lock()
            }
            stateLock.unlock()
        }
    }
    recvThread.start()

    // Send Loop (Main Thread)
    while true {
        print("> ", terminator: "")
        fflush(stdout)
        guard let msg = readLine(), !msg.isEmpty else { continue }

        stateLock.lock()
        let seq = sendSeq
        sendSeq += 1
        stateLock.unlock()

        let msgBytes = Data(msg.utf8)
        let digest = sha256Digest(msgBytes)

        var payload = Data()
        var seqLE = seq.littleEndian
        payload.append(Data(bytes: &seqLE, count: 4))
        payload.append(identityPub)
        payload.append(pIdPub)
        payload.append(msgBytes)

        guard let sig = try? identity.signature(for: payload) else {
            print("[!] Failed to sign message")
            continue
        }

        // Layout: [sig (64)] [sha256 digest (32)] [plaintext...]
        var innerBytes = Data()
        innerBytes.append(sig)
        innerBytes.append(digest)
        innerBytes.append(msgBytes)
        let innerStr = innerBytes.base64EncodedString()

        let (k1, k2, nonce) = sendRatchet.step()
        let encryptedList = encrypt(innerStr, k1, k2, nonce)

        var pkt = Data([PKT_CHAT])
        pkt.append(Data(bytes: &seqLE, count: 4))
        pkt.append(serialize_crypt(encryptedList))

        sendUDP(sockfd: sockfd, data: pkt, to: peerIP, port: peerPort)
    }
}

main()
