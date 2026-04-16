use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

// ---------------------------------------------------------------------------
// TLV8 tags
// ---------------------------------------------------------------------------
#[allow(dead_code)]
mod tag {
    pub const IDENTIFIER: u8 = 1;
    pub const SALT: u8 = 2;
    pub const PUBLICKEY: u8 = 3;
    pub const PROOF: u8 = 4;
    pub const ENCRYPTEDDATA: u8 = 5;
    pub const STATE: u8 = 6;
    pub const ERROR: u8 = 7;
    pub const SIGNATURE: u8 = 10;
    pub const FLAGS: u8 = 19;
    pub const METHOD: u8 = 0;
}

// ---------------------------------------------------------------------------
// TLV8 codec
// ---------------------------------------------------------------------------
pub mod tlv {
    use std::collections::HashMap;

    /// Decode TLV8 bytes into a tag -> value map.
    /// If the same tag appears multiple times the values are concatenated.
    pub fn decode(data: &[u8]) -> HashMap<u8, Vec<u8>> {
        let mut map: HashMap<u8, Vec<u8>> = HashMap::new();
        let mut i = 0;
        while i + 1 < data.len() {
            let t = data[i];
            let l = data[i + 1] as usize;
            i += 2;
            let v = &data[i..i + l.min(data.len().saturating_sub(i))];
            map.entry(t).or_default().extend_from_slice(v);
            i += l;
        }
        map
    }

    /// Encode items into TLV8 bytes.
    /// Values longer than 255 bytes are split into multiple chunks.
    pub fn encode(items: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(t, v) in items {
            if v.is_empty() {
                out.push(t);
                out.push(0);
            } else {
                let mut offset = 0;
                while offset < v.len() {
                    let chunk_len = (v.len() - offset).min(255);
                    out.push(t);
                    out.push(chunk_len as u8);
                    out.extend_from_slice(&v[offset..offset + chunk_len]);
                    offset += chunk_len;
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// HKDF helpers (HMAC-SHA-256 based, single-block expand)
// ---------------------------------------------------------------------------

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    assert!(length <= 32, "single-block expand: length must be <= 32");
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(prk).expect("HMAC accepts any key size");
    mac.update(info);
    mac.update(&[0x01u8]);
    mac.finalize().into_bytes()[..length].to_vec()
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 helpers (12-byte nonce, zero-padded from 8-byte counter)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 helpers
// ---------------------------------------------------------------------------

/// Pad a nonce to 12 bytes by left-padding with zeros (matching Python rjust).
fn pad_nonce(nonce_bytes: &[u8]) -> Nonce {
    let mut n = [0u8; 12];
    let start = 12 - nonce_bytes.len().min(12);
    n[start..].copy_from_slice(&nonce_bytes[..nonce_bytes.len().min(12)]);
    *Nonce::from_slice(&n)
}

/// Build a 12-byte nonce from a little-endian u64 counter (for HAP framing).
fn counter_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

/// Encrypt with a string nonce and no AAD (used by pair-setup/pair-verify).
fn cc_encrypt(key: &[u8; 32], nonce_bytes: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = pad_nonce(nonce_bytes);
    cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption never fails with valid inputs")
}

/// Decrypt with a string nonce and no AAD (used by pair-setup/pair-verify).
fn cc_decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = pad_nonce(nonce_bytes);
    cipher.decrypt(&nonce, ciphertext_with_tag)
}

/// Encrypt with counter nonce and AAD (used by HAP encrypted framing).
fn hap_chacha_encrypt(key: &[u8; 32], counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter_nonce(counter);
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encryption never fails with valid inputs")
}

/// Decrypt with counter nonce and AAD (used by HAP encrypted framing).
fn hap_chacha_decrypt(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter_nonce(counter);
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad })
}

// ---------------------------------------------------------------------------
// SRP-6a (3072-bit, SHA-512, g=5)
// ---------------------------------------------------------------------------

/// The 3072-bit safe prime N from RFC 5054.
fn srp_n() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
          8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
          302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
          A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
          49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
          FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
          670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
          180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
          3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
          04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
          B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
          1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
          BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
          E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16,
    )
    .expect("valid hex")
}

const SRP_PAD: usize = 384; // 3072 / 8
const SRP_G: u64 = 5;

/// An argument to `srp_hash`.
enum SrpHashArg<'a> {
    /// A big integer: converted to minimal big-endian bytes (no leading zeros).
    Int(&'a BigUint),
    /// Raw bytes: used as-is.
    Bytes(&'a [u8]),
}

/// Python `_H` equivalent.
///
/// For each argument:
///   - `Int(n)`   → minimal big-endian bytes of `n` (same as Python `int.to_bytes(max(1, …), "big")`)
///   - `Bytes(b)` → `b` as-is
///
/// If `pad` is true every part is left-padded with `\x00` to `SRP_PAD` bytes.
/// All parts are joined with `sep` and hashed with SHA-512.
/// The digest is returned as a `BigUint` (leading zero bytes are automatically dropped).
fn srp_hash(args: &[SrpHashArg], pad: bool, sep: &[u8]) -> BigUint {
    // Build each part as a Vec<u8>.
    let parts: Vec<Vec<u8>> = args
        .iter()
        .map(|a| {
            let raw: Vec<u8> = match a {
                SrpHashArg::Int(n) => {
                    let b = n.to_bytes_be();
                    // Python: max(1, (n.bit_length() + 7) // 8) bytes
                    // BigUint::to_bytes_be() returns [] for zero; ensure at least 1 byte.
                    if b.is_empty() { vec![0u8] } else { b }
                }
                SrpHashArg::Bytes(b) => b.to_vec(),
            };
            if pad {
                // left-pad to SRP_PAD
                if raw.len() < SRP_PAD {
                    let mut padded = vec![0u8; SRP_PAD - raw.len()];
                    padded.extend_from_slice(&raw);
                    padded
                } else {
                    raw
                }
            } else {
                raw
            }
        })
        .collect();

    // Join parts with separator and hash.
    let mut hasher = Sha512::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 && !sep.is_empty() {
            hasher.update(sep);
        }
        hasher.update(part);
    }
    BigUint::from_bytes_be(&hasher.finalize())
}

struct SrpServer {
    username: Vec<u8>,
    _s: BigUint,         // salt (random bytes as integer)
    _b: BigUint,         // server private ephemeral
    _b_pub: BigUint,     // B = k*v + g^b mod N
    _v: BigUint,         // verifier
    _a_pub: BigUint,     // client public A (set later)
    _k_session: BigUint, // session key K = H(S)
    _m1: BigUint,        // expected client proof M1
    _m2: BigUint,        // server proof M2
    n: BigUint,
}

impl SrpServer {
    /// `username` and `password` are raw bytes, matching Python `_SRPServer.__init__`.
    fn new(username: &[u8], password: &[u8]) -> Self {
        let n = srp_n();
        let g = BigUint::from(SRP_G);

        // k = H(N, g, pad=True)
        let k = srp_hash(&[SrpHashArg::Int(&n), SrpHashArg::Int(&g)], true, b"");

        // salt: 16 random bytes (matches Python _rand(128) → 128-bit)
        let mut salt_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let s = BigUint::from_bytes_be(&salt_bytes);

        // x = H(s, H(username, password, sep=b":"))
        // Inner hash: H(username:password) — username and password are bytes args.
        let inner = srp_hash(
            &[SrpHashArg::Bytes(username), SrpHashArg::Bytes(password)],
            false,
            b":",
        );
        // Outer hash: H(s, inner) — s is Int (minimal bytes), inner is Int (minimal bytes).
        let x = srp_hash(&[SrpHashArg::Int(&s), SrpHashArg::Int(&inner)], false, b"");

        // v = g^x mod N
        let v = g.modpow(&x, &n);

        // b: 512-bit random ephemeral (matches Python _rand() → default 512-bit)
        let mut b_bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut b_bytes);
        let b = BigUint::from_bytes_be(&b_bytes) % &n;

        // B = (k*v + g^b) mod N
        let b_pub = ((&k * &v) + g.modpow(&b, &n)) % &n;

        SrpServer {
            username: username.to_vec(),
            _s: s,
            _b: b,
            _b_pub: b_pub,
            _v: v,
            _a_pub: BigUint::from(0u32),
            _k_session: BigUint::from(0u32),
            _m1: BigUint::from(0u32),
            _m2: BigUint::from(0u32),
            n,
        }
    }

    fn salt_bytes(&self) -> Vec<u8> {
        // Matches Python _to_bytes(self._s) — minimal big-endian bytes.
        let b = self._s.to_bytes_be();
        if b.is_empty() { vec![0u8] } else { b }
    }

    fn b_pub_bytes(&self) -> Vec<u8> {
        self._b_pub.to_bytes_be()
    }

    fn set_client_public(&mut self, a_bytes: &[u8]) {
        let n = self.n.clone();
        let a = BigUint::from_bytes_be(a_bytes);
        self._a_pub = a.clone();

        // u = H(A, B, pad=True)
        let u = srp_hash(
            &[SrpHashArg::Int(&a), SrpHashArg::Int(&self._b_pub)],
            true,
            b"",
        );

        // S = (A * v^u mod N)^b mod N
        let s = (a.clone() * self._v.modpow(&u, &n)).modpow(&self._b, &n) % &n;

        // K = H(S)  — S is Int (minimal bytes), no padding, no sep
        self._k_session = srp_hash(&[SrpHashArg::Int(&s)], false, b"");

        // M1 = H( H(N) ^ H(g),  H(username),  s,  A,  B,  K )
        //
        // H(N): hash N's minimal bytes (N is 384 bytes, no leading zeros) — NOT padded
        // H(g): hash g's minimal bytes (1 byte: \x05)                    — NOT padded
        // XOR is INTEGER xor of the two BigUint results.
        let hn: BigUint = srp_hash(&[SrpHashArg::Int(&n)], false, b"");
        let hg: BigUint = srp_hash(&[SrpHashArg::Int(&BigUint::from(SRP_G))], false, b"");
        let xor_int: BigUint = hn ^ hg;

        // H(username) — username is bytes
        let hu: BigUint = srp_hash(&[SrpHashArg::Bytes(&self.username)], false, b"");

        // All args to M1 hash are Int (minimal bytes), no padding, no sep.
        self._m1 = srp_hash(
            &[
                SrpHashArg::Int(&xor_int),
                SrpHashArg::Int(&hu),
                SrpHashArg::Int(&self._s),
                SrpHashArg::Int(&a),
                SrpHashArg::Int(&self._b_pub),
                SrpHashArg::Int(&self._k_session),
            ],
            false,
            b"",
        );

        // M2 = H(A, M1, K)
        let m1 = self._m1.clone();
        let k = self._k_session.clone();
        self._m2 = srp_hash(
            &[
                SrpHashArg::Int(&a),
                SrpHashArg::Int(&m1),
                SrpHashArg::Int(&k),
            ],
            false,
            b"",
        );
    }

    fn verify_client_proof(&self, proof: &[u8]) -> bool {
        BigUint::from_bytes_be(proof) == self._m1
    }

    fn server_proof_bytes(&self) -> Vec<u8> {
        self._m2.to_bytes_be()
    }

    fn session_key_bytes(&self) -> Vec<u8> {
        // Exactly 64 bytes: K.to_bytes(64, "big") — left-pad with zeros.
        let b = self._k_session.to_bytes_be();
        if b.len() >= 64 {
            b[b.len() - 64..].to_vec()
        } else {
            let mut padded = vec![0u8; 64 - b.len()];
            padded.extend_from_slice(&b);
            padded
        }
    }
}

// ---------------------------------------------------------------------------
// FairPlay stub
// ---------------------------------------------------------------------------

static FP_REPLIES: [&[u8]; 4] = [
    b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x00\x0f\x9f\x3f\x9e\x0a\x25\x21\xdb\xdf\x31\x2a\xb2\xbf\xb2\x9e\x8d\x23\x2b\x63\x76\xa8\xc8\x18\x70\x1d\x22\xae\x93\xd8\x27\x37\xfe\xaf\x9d\xb4\xfd\xf4\x1c\x2d\xba\x9d\x1f\x49\xca\xaa\xbf\x65\x91\xac\x1f\x7b\xc6\xf7\xe0\x66\x3d\x21\xaf\xe0\x15\x65\x95\x3e\xab\x81\xf4\x18\xce\xed\x09\x5a\xdb\x7c\x3d\x0e\x25\x49\x09\xa7\x98\x31\xd4\x9c\x39\x82\x97\x34\x34\xfa\xcb\x42\xc6\x3a\x1c\xd9\x11\xa6\xfe\x94\x1a\x8a\x6d\x4a\x74\x3b\x46\xc3\xa7\x64\x9e\x44\xc7\x89\x55\xe4\x9d\x81\x55\x00\x95\x49\xc4\xe2\xf7\xa3\xf6\xd5\xba",
    b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x01\xcf\x32\xa2\x57\x14\xb2\x52\x4f\x8a\xa0\xad\x7a\xf1\x64\xe3\x7b\xcf\x44\x24\xe2\x00\x04\x7e\xfc\x0a\xd6\x7a\xfc\xd9\x5d\xed\x1c\x27\x30\xbb\x59\x1b\x96\x2e\xd6\x3a\x9c\x4d\xed\x88\xba\x8f\xc7\x8d\xe6\x4d\x91\xcc\xfd\x5c\x7b\x56\xda\x88\xe3\x1f\x5c\xce\xaf\xc7\x43\x19\x95\xa0\x16\x65\xa5\x4e\x19\x39\xd2\x5b\x94\xdb\x64\xb9\xe4\x5d\x8d\x06\x3e\x1e\x6a\xf0\x7e\x96\x56\x16\x2b\x0e\xfa\x40\x42\x75\xea\x5a\x44\xd9\x59\x1c\x72\x56\xb9\xfb\xe6\x51\x38\x98\xb8\x02\x27\x72\x19\x88\x57\x16\x50\x94\x2a\xd9\x46\x68\x8a",
    b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x02\xc1\x69\xa3\x52\xee\xed\x35\xb1\x8c\xdd\x9c\x58\xd6\x4f\x16\xc1\x51\x9a\x89\xeb\x53\x17\xbd\x0d\x43\x36\xcd\x68\xf6\x38\xff\x9d\x01\x6a\x5b\x52\xb7\xfa\x92\x16\xb2\xb6\x54\x82\xc7\x84\x44\x11\x81\x21\xa2\xc7\xfe\xd8\x3d\xb7\x11\x9e\x91\x82\xaa\xd7\xd1\x8c\x70\x63\xe2\xa4\x57\x55\x59\x10\xaf\x9e\x0e\xfc\x76\x34\x7d\x16\x40\x43\x80\x7f\x58\x1e\xe4\xfb\xe4\x2c\xa9\xde\xdc\x1b\x5e\xb2\xa3\xaa\x3d\x2e\xcd\x59\xe7\xee\xe7\x0b\x36\x29\xf2\x2a\xfd\x16\x1d\x87\x73\x53\xdd\xb9\x9a\xdc\x8e\x07\x00\x6e\x56\xf8\x50\xce",
    b"\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x03\x90\x01\xe1\x72\x7e\x0f\x57\xf9\xf5\x88\x0d\xb1\x04\xa6\x25\x7a\x23\xf5\xcf\xff\x1a\xbb\xe1\xe9\x30\x45\x25\x1a\xfb\x97\xeb\x9f\xc0\x01\x1e\xbe\x0f\x3a\x81\xdf\x5b\x69\x1d\x76\xac\xb2\xf7\xa5\xc7\x08\xe3\xd3\x28\xf5\x6b\xb3\x9d\xbd\xe5\xf2\x9c\x8a\x17\xf4\x81\x48\x7e\x3a\xe8\x63\xc6\x78\x32\x54\x22\xe6\xf7\x8e\x16\x6d\x18\xaa\x7f\xd6\x36\x25\x8b\xce\x28\x72\x6f\x66\x1f\x73\x88\x93\xce\x44\x31\x1e\x4b\xe6\xc0\x53\x51\x93\xe5\xef\x72\xe8\x68\x62\x33\x72\x9c\x22\x7d\x82\x0c\x99\x94\x45\xd8\x92\x46\xc8\xc3\x59",
];

const FP_HEADER: &[u8] = &[
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14,
];

/// Handle a FairPlay setup request and return the appropriate response, or `None`.
pub fn fairplay_setup(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 15 {
        return None;
    }
    if request[4] != 3 {
        return None;
    }
    let type_ = request[5];
    let seq = request[6];
    if type_ == 1 && seq == 1 {
        let mode = request[14] as usize;
        if mode < 4 {
            Some(FP_REPLIES[mode].to_vec())
        } else {
            None
        }
    } else if type_ == 1 && seq == 3 {
        let tail = &request[request.len().saturating_sub(20)..];
        let mut out = FP_HEADER.to_vec();
        out.extend_from_slice(tail);
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// HapSession
// ---------------------------------------------------------------------------

/// Pair-setup and pair-verify session for AirPlay 2 (transient, no persistent long-term keys).
pub struct HapSession {
    identifier: Vec<u8>,
    ltsk: SigningKey,
    ltpk: VerifyingKey,
    srp: Option<SrpServer>,
    // pair_verify state
    verify_our_pub: Option<X25519PublicKey>,
    verify_shared: Option<[u8; 32]>,
    pub encrypted: bool,
    pub shared_key: Option<Vec<u8>>,
}

impl HapSession {
    pub fn new(ltsk: SigningKey) -> Self {
        let ltpk = ltsk.verifying_key();
        Self {
            identifier: b"AirPlayReceiver".to_vec(),
            ltsk,
            ltpk,
            srp: None,
            verify_our_pub: None,
            verify_shared: None,
            encrypted: false,
            shared_key: None,
        }
    }

    pub fn public_key_hex(&self) -> String {
        ::hex::encode(self.ltpk.as_bytes())
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn shared_key(&self) -> Option<&[u8]> {
        self.shared_key.as_deref()
    }

    // ------------------------------------------------------------------
    // Pair-setup (SRP transient flow)
    // ------------------------------------------------------------------

    /// Process a pair-setup request body (TLV8) and return a TLV8 response.
    pub fn pair_setup(&mut self, body: &[u8]) -> Vec<u8> {
        let tlv_in = tlv::decode(body);
        let state = tlv_in.get(&tag::STATE).and_then(|v| v.first().copied()).unwrap_or(0);

        match state {
            // M1: client hello -> M2: salt + B
            0x01 => {
                let srp = SrpServer::new(b"Pair-Setup", b"3939");
                let salt = srp.salt_bytes();
                let b_pub = srp.b_pub_bytes();
                self.srp = Some(srp);
                tlv::encode(&[
                    (tag::STATE, &[0x02]),
                    (tag::SALT, &salt),
                    (tag::PUBLICKEY, &b_pub),
                ])
            }
            // M3: client proof -> M4: server proof
            0x03 => {
                let a_pub = tlv_in.get(&tag::PUBLICKEY).cloned().unwrap_or_default();
                let m1_proof = tlv_in.get(&tag::PROOF).cloned().unwrap_or_default();
                let srp = match self.srp.as_mut() {
                    Some(s) => s,
                    None => {
                        return tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x02])])
                    }
                };
                srp.set_client_public(&a_pub);
                if !srp.verify_client_proof(&m1_proof) {
                    return tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x04])]);
                }
                let m2 = srp.server_proof_bytes();
                // Store the raw SRP session key (64 bytes) — NOT HKDF-derived.
                // This matches Python: self.shared_key = self._srp.session_key
                // The HAP codec later derives Control channel keys from this.
                self.shared_key = Some(srp.session_key_bytes());
                self.encrypted = true;
                tlv::encode(&[(tag::STATE, &[0x04]), (tag::PROOF, &m2)])
            }
            _ => tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x02])]),
        }
    }

    // ------------------------------------------------------------------
    // Pair-verify (X25519 + Ed25519)
    // ------------------------------------------------------------------

    /// Process a pair-verify request body (TLV8) and return a TLV8 response.
    pub fn pair_verify(&mut self, body: &[u8]) -> Vec<u8> {
        let tlv_in = tlv::decode(body);
        let state = tlv_in.get(&tag::STATE).and_then(|v| v.first().copied()).unwrap_or(0);

        match state {
            // M1: client X25519 pub -> M2: our X25519 pub + Ed25519 sig
            0x01 => {
                let client_pub_bytes = tlv_in.get(&tag::PUBLICKEY).cloned().unwrap_or_default();

                // Generate our ephemeral X25519 keypair
                let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
                let our_pub = X25519PublicKey::from(&secret);

                // Compute shared secret
                let client_pub_arr: [u8; 32] = match client_pub_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return tlv::encode(&[(tag::STATE, &[0x02]), (tag::ERROR, &[0x02])])
                    }
                };
                let client_pub = X25519PublicKey::from(client_pub_arr);
                let shared = secret.diffie_hellman(&client_pub);
                let shared_bytes = shared.as_bytes().clone();

                // Derive session key via HKDF-SHA-256
                let prk = hkdf_extract_sha256(b"Pair-Verify-Encrypt-Salt", &shared_bytes);
                let session_key_vec =
                    hkdf_expand_sha256(&prk, b"Pair-Verify-Encrypt-Info", 32);
                let mut session_key = [0u8; 32];
                session_key.copy_from_slice(&session_key_vec);

                // Build info = our_pub || identifier || client_pub
                let mut info = Vec::new();
                info.extend_from_slice(our_pub.as_bytes());
                info.extend_from_slice(&self.identifier);
                info.extend_from_slice(&client_pub_bytes);

                // Sign info with our Ed25519 long-term key
                use ed25519_dalek::Signer;
                let signature = self.ltsk.sign(&info);

                // Encrypt (identifier || signature) with session key, nonce counter=0
                let mut sub_tlv_plain = Vec::new();
                sub_tlv_plain.extend_from_slice(&tlv::encode(&[
                    (tag::IDENTIFIER, &self.identifier),
                    (tag::SIGNATURE, signature.to_bytes().as_slice()),
                ]));
                let encrypted_data = cc_encrypt(&session_key, b"PV-Msg02", &sub_tlv_plain);

                // Save state for M3
                self.verify_shared = Some(shared_bytes);
                // Reuse verify_our_pub slot to store session key (via a small hack)
                self.verify_our_pub = Some(our_pub);
                // We need session_key in M3 as well; store in shared_key temporarily
                self.shared_key = Some(session_key.to_vec());

                tlv::encode(&[
                    (tag::STATE, &[0x02]),
                    (tag::PUBLICKEY, our_pub.as_bytes()),
                    (tag::ENCRYPTEDDATA, &encrypted_data),
                ])
            }
            // M3: client encrypted verify -> M4: ok / error
            0x03 => {
                let enc_data = tlv_in.get(&tag::ENCRYPTEDDATA).cloned().unwrap_or_default();
                let session_key_vec = match self.shared_key.take() {
                    Some(k) => k,
                    None => {
                        return tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x02])])
                    }
                };
                let mut session_key = [0u8; 32];
                session_key.copy_from_slice(&session_key_vec);

                let plain = match cc_decrypt(&session_key, b"PV-Msg03", &enc_data) {
                    Ok(p) => p,
                    Err(_) => {
                        return tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x06])])
                    }
                };
                // We simply accept any decryptable message (transient pairing)
                let _ = tlv::decode(&plain);

                // Activate encryption using the X25519 shared secret
                let shared = match self.verify_shared.take() {
                    Some(s) => s,
                    None => {
                        return tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x02])])
                    }
                };
                self.shared_key = Some(shared.to_vec());
                self.encrypted = true;

                tlv::encode(&[(tag::STATE, &[0x04])])
            }
            _ => tlv::encode(&[(tag::STATE, &[0x04]), (tag::ERROR, &[0x02])]),
        }
    }
}

// ---------------------------------------------------------------------------
// HapCodec - encrypted framing for the control channel
// ---------------------------------------------------------------------------

/// Derive the two 32-byte ChaCha20-Poly1305 keys from the HAP shared secret.
/// Uses HKDF-SHA-512 (extract then single-block expand).
fn derive_hap_keys(shared_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    // extract
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(b"Control-Salt").expect("HMAC accepts any key size");
    mac.update(shared_key);
    let prk = mac.finalize().into_bytes();

    // out_key = HMAC-SHA512(prk, "Control-Read-Encryption-Key\x01")[:32]
    let mut mac2 = <Hmac<Sha512> as Mac>::new_from_slice(&prk).expect("HMAC");
    mac2.update(b"Control-Read-Encryption-Key\x01");
    let out_full = mac2.finalize().into_bytes();

    // in_key = HMAC-SHA512(prk, "Control-Write-Encryption-Key\x01")[:32]
    let mut mac3 = <Hmac<Sha512> as Mac>::new_from_slice(&prk).expect("HMAC");
    mac3.update(b"Control-Write-Encryption-Key\x01");
    let in_full = mac3.finalize().into_bytes();

    let mut out_key = [0u8; 32];
    let mut in_key = [0u8; 32];
    out_key.copy_from_slice(&out_full[..32]);
    in_key.copy_from_slice(&in_full[..32]);
    (out_key, in_key)
}

const HAP_BLOCK_SIZE: usize = 1024;

/// Stateful encrypt/decrypt codec for the HAP encrypted control channel.
pub struct HapCodec {
    out_key: [u8; 32],
    in_key: [u8; 32],
    out_counter: u64,
    in_counter: u64,
}

impl HapCodec {
    pub fn new(shared_key: &[u8]) -> Self {
        let (out_key, in_key) = derive_hap_keys(shared_key);
        Self {
            out_key,
            in_key,
            out_counter: 0,
            in_counter: 0,
        }
    }

    /// Encrypt plaintext into HAP framed ciphertext (may contain multiple blocks).
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(HAP_BLOCK_SIZE) {
            let length = chunk.len() as u16;
            let aad = length.to_le_bytes();
            let ct = hap_chacha_encrypt(&self.out_key, self.out_counter, &aad, chunk);
            // ct includes the 16-byte Poly1305 tag at the end
            out.extend_from_slice(&aad);
            out.extend_from_slice(&ct);
            self.out_counter += 1;
        }
        out
    }

    /// Decrypt HAP framed ciphertext back into plaintext.
    /// Consumes as many complete frames as are present in `data`.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 2 <= data.len() {
            let length = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            let frame_end = pos + 2 + length + 16;
            if frame_end > data.len() {
                break; // incomplete frame
            }
            let aad = &data[pos..pos + 2];
            let ct = &data[pos + 2..frame_end];
            match hap_chacha_decrypt(&self.in_key, self.in_counter, aad, ct) {
                Ok(plain) => {
                    out.extend_from_slice(&plain);
                    self.in_counter += 1;
                }
                Err(_) => {
                    // decryption failure — stop processing
                    break;
                }
            }
            pos = frame_end;
        }
        out
    }
}

