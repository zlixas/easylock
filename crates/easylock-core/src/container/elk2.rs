//! The **ELK2** header: a random 256-bit *file key* wrapped by one or more
//! *key slots*, followed by an HMAC over the whole header.
//!
//! Slots come in two kinds:
//!
//! * **password**: `Argon2id(password, salt)` → KEK;
//! * **recipient** (public key): X25519 **and** ML-KEM-768 hybrid, so the file stays
//!   secret as long as *either* problem stays hard (post-quantum by default).
//!
//! Any single slot recovers the file key. The header MAC is keyed from the file key, so
//! an attacker who can't open a slot can't add, remove or modify slots, flags or the
//! cipher without detection. See `docs/FILE_FORMAT.md` for the byte layout.

use super::Cipher;
use crate::aead::{Aead, ChaCha20Poly1305};
use crate::ct::ct_eq;
use crate::ec::x25519::{x25519, x25519_base};
use crate::encode::base64;
use crate::hash::{sha256, Sha256};
use crate::kdf::argon2::{self, Params};
use crate::kdf::Hkdf;
use crate::mac::Hmac;
use crate::pqc::mlkem::{self, MlKem768};
use crate::secure::Zeroize;
use crate::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

/// ELK2 magic.
pub const MAGIC: &[u8; 4] = b"ELK2";
/// Header flag: the payload is an easylock folder archive (see `archive`).
pub const FLAG_ARCHIVE: u8 = 0x01;
const KNOWN_FLAGS: u8 = FLAG_ARCHIVE;

/// Slot type: password (Argon2id).
pub const SLOT_PASSWORD: u8 = 1;
/// Slot type: X25519 + ML-KEM-768 recipient.
pub const SLOT_HYBRID: u8 = 2;

/// Length of the trailing header MAC (HMAC-SHA-256).
pub const MAC_LEN: usize = 32;
const WRAPPED_LEN: usize = 32 + 16;
const CT_LEN: usize = MlKem768.ct_len();
const EK_LEN: usize = MlKem768.ek_len();
const PASSWORD_BODY: usize = 12 + 16 + WRAPPED_LEN;
const HYBRID_BODY: usize = 32 + CT_LEN + WRAPPED_LEN;

/// Largest Argon2 memory cost accepted when *reading* a file (4 GiB), so a hostile
/// header can't make the reader allocate unbounded memory.
pub const MAX_M_COST: u32 = 4 * 1024 * 1024;
/// Largest Argon2 time cost accepted when reading.
pub const MAX_T_COST: u32 = 64;
/// Largest Argon2 parallelism accepted when reading.
pub const MAX_PARALLELISM: u32 = 64;
/// Most key slots in one header.
pub const MAX_SLOTS: usize = 64;

/// Reject Argon2 parameters outside the accepted range.
pub(crate) fn check_params(p: &Params) -> Result<()> {
    if p.m_cost > MAX_M_COST
        || p.t_cost == 0
        || p.t_cost > MAX_T_COST
        || p.parallelism == 0
        || p.parallelism > MAX_PARALLELISM
        || p.m_cost < 8 * p.parallelism
    {
        return Err(Error::InvalidParameter {
            what: "argon2 parameters outside the accepted range",
        });
    }
    Ok(())
}

fn to32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

// ---------------------------------------------------------------- file key

/// The random per-file key. Zeroized on drop.
pub struct FileKey([u8; 32]);

impl FileKey {
    fn random(rng: &mut impl FnMut(&mut [u8])) -> Self {
        let mut k = [0u8; 32];
        rng(&mut k);
        FileKey(k)
    }

    /// AEAD key for the payload chunks.
    #[must_use]
    pub fn payload_key(&self, base_nonce: &[u8; 12]) -> [u8; 32] {
        let mut v = Hkdf::<Sha256>::derive(base_nonce, &self.0, b"elk2 payload", 32)
            .expect("32 bytes is a valid HKDF length");
        let k = to32(&v);
        v.zeroize();
        k
    }

    fn header_mac(&self, header: &[u8]) -> Vec<u8> {
        let mut mk = Hkdf::<Sha256>::derive(&[], &self.0, b"elk2 header mac", 32)
            .expect("32 bytes is a valid HKDF length");
        let tag = Hmac::<Sha256>::mac(&mk, header);
        mk.zeroize();
        tag
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FileKey(<redacted>)")
    }
}

fn wrap(kek: &[u8], slot: u8, fk: &FileKey) -> Result<[u8; WRAPPED_LEN]> {
    // Each KEK is unique (fresh salt / fresh ephemeral key), so a fixed nonce is safe.
    let ct = ChaCha20Poly1305::new(kek)?.seal(&[0u8; 12], &[b'e', b'l', b'k', b'2', slot], &fk.0);
    let mut out = [0u8; WRAPPED_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

fn unwrap(kek: &[u8], slot: u8, wrapped: &[u8; WRAPPED_LEN]) -> Result<FileKey> {
    let mut pt =
        ChaCha20Poly1305::new(kek)?.open(&[0u8; 12], &[b'e', b'l', b'k', b'2', slot], wrapped)?;
    let fk = FileKey(to32(&pt));
    pt.zeroize();
    Ok(fk)
}

fn hybrid_kek(
    ss_x: &[u8; 32],
    ss_k: &[u8],
    eph_pub: &[u8; 32],
    recip_x: &[u8; 32],
    ct: &[u8],
) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_k);
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recip_x);
    let mut info = Vec::with_capacity(20 + 32);
    info.extend_from_slice(b"elk2 x25519+mlkem768");
    info.extend_from_slice(&sha256::hash(ct));
    let kek = Hkdf::<Sha256>::derive(&salt, &ikm, &info, 32).expect("valid HKDF length");
    ikm.zeroize();
    kek
}

// ------------------------------------------------------- identities & recipients

const RECIPIENT_PREFIX: &str = "elkpub1";
const IDENTITY_PREFIX: &str = "ELK-SECRET-KEY-1";

fn checksum(prefix: &str, body: &[u8]) -> [u8; 4] {
    let mut h = Vec::with_capacity(prefix.len() + body.len());
    h.extend_from_slice(prefix.as_bytes());
    h.extend_from_slice(body);
    let d = sha256::hash(&h);
    [d[0], d[1], d[2], d[3]]
}

fn encode_key(prefix: &str, body: &[u8]) -> String {
    let mut v = body.to_vec();
    v.extend_from_slice(&checksum(prefix, body));
    let s = alloc::format!("{prefix}{}", base64::encode(&v, base64::Variant::UrlNoPad));
    v.zeroize();
    s
}

fn decode_key(prefix: &str, s: &str, len: usize) -> Result<Vec<u8>> {
    let bad = || Error::InvalidEncoding {
        scheme: "easylock key (wrong prefix, length or checksum)",
    };
    let body = s.trim().strip_prefix(prefix).ok_or_else(bad)?;
    let mut v = base64::decode(body, base64::Variant::UrlNoPad).map_err(|_| bad())?;
    if v.len() != len + 4 || !bool::from(ct_eq(&v[len..], &checksum(prefix, &v[..len]))) {
        v.zeroize();
        return Err(bad());
    }
    v.truncate(len);
    Ok(v)
}

/// A public key that files can be encrypted *to* (`elkpub1…`).
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient {
    x25519: [u8; 32],
    mlkem_ek: Vec<u8>,
}

impl Recipient {
    /// Parse an `elkpub1…` string.
    pub fn parse(s: &str) -> Result<Self> {
        let v = decode_key(RECIPIENT_PREFIX, s, 32 + EK_LEN)?;
        Ok(Recipient {
            x25519: to32(&v[..32]),
            mlkem_ek: v[32..].to_vec(),
        })
    }

    /// Encode as an `elkpub1…` string.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut body = self.x25519.to_vec();
        body.extend_from_slice(&self.mlkem_ek);
        encode_key(RECIPIENT_PREFIX, &body)
    }

    /// Short human-comparable fingerprint (`ab12:cd34:…`, 64 bits of SHA-256).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut body = self.x25519.to_vec();
        body.extend_from_slice(&self.mlkem_ek);
        let d = sha256::hash(&body);
        let mut s = String::new();
        for (i, pair) in d[..8].chunks(2).enumerate() {
            if i > 0 {
                s.push(':');
            }
            s.push_str(&crate::encode::hex::encode(pair));
        }
        s
    }
}

impl core::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Recipient({})", self.fingerprint())
    }
}

/// A secret identity (`ELK-SECRET-KEY-1…`): an X25519 key and an ML-KEM-768 seed.
pub struct Identity {
    x_sk: [u8; 32],
    seed: [u8; 64],
    x_pub: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
}

impl Identity {
    /// Generate a fresh identity.
    pub fn generate(rng: &mut impl FnMut(&mut [u8])) -> Self {
        let mut secret = [0u8; 96];
        rng(&mut secret);
        let id = Self::from_secret(&secret);
        secret.zeroize();
        id
    }

    fn from_secret(secret: &[u8]) -> Self {
        let x_sk = to32(&secret[..32]);
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&secret[32..96]);
        let (ek, dk) = mlkem::keygen_derand(&MlKem768, &to32(&seed[..32]), &to32(&seed[32..]));
        Identity {
            x_pub: x25519_base(&x_sk),
            x_sk,
            seed,
            ek,
            dk,
        }
    }

    /// Parse an `ELK-SECRET-KEY-1…` string.
    pub fn parse(s: &str) -> Result<Self> {
        let mut v = decode_key(IDENTITY_PREFIX, s, 96)?;
        let id = Self::from_secret(&v);
        v.zeroize();
        Ok(id)
    }

    /// Encode the secret as an `ELK-SECRET-KEY-1…` string. Handle with care.
    #[must_use]
    pub fn encode_secret(&self) -> String {
        let mut body = [0u8; 96];
        body[..32].copy_from_slice(&self.x_sk);
        body[32..].copy_from_slice(&self.seed);
        let s = encode_key(IDENTITY_PREFIX, &body);
        body.zeroize();
        s
    }

    /// The matching public key.
    #[must_use]
    pub fn recipient(&self) -> Recipient {
        Recipient {
            x25519: self.x_pub,
            mlkem_ek: self.ek.clone(),
        }
    }

    fn try_unwrap(
        &self,
        eph_pub: &[u8; 32],
        ct: &[u8],
        wrapped: &[u8; WRAPPED_LEN],
    ) -> Result<FileKey> {
        let mut ss_x = x25519(&self.x_sk, eph_pub);
        let mut ss_k = mlkem::decaps(&MlKem768, &self.dk, ct)?;
        let mut kek = hybrid_kek(&ss_x, &ss_k, eph_pub, &self.x_pub, ct);
        ss_x.zeroize();
        ss_k.zeroize();
        let r = unwrap(&kek, SLOT_HYBRID, wrapped);
        kek.zeroize();
        r
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.x_sk.zeroize();
        self.seed.zeroize();
        self.dk.zeroize();
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({})", self.recipient().fingerprint())
    }
}

// ------------------------------------------------------------------ building

/// One key slot to create when encrypting.
#[derive(Debug, Clone)]
pub enum SlotSpec<'a> {
    /// Unlockable with this password.
    Password {
        /// The password bytes.
        password: &'a [u8],
        /// Argon2id cost.
        params: Params,
    },
    /// Unlockable with the matching [`Identity`].
    Recipient(&'a Recipient),
}

/// Output of [`build`].
#[derive(Debug)]
pub struct Built {
    /// Complete header bytes (including the MAC).
    pub header: Vec<u8>,
    /// The file key the payload must be encrypted under.
    pub file_key: FileKey,
    /// Base nonce for the payload chunks.
    pub base_nonce: [u8; 12],
}

/// Build an ELK2 header.
///
/// `rng` must fill buffers with cryptographically secure randomness.
pub fn build(
    cipher: Cipher,
    flags: u8,
    slots: &[SlotSpec<'_>],
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<Built> {
    if slots.is_empty() || slots.len() > MAX_SLOTS {
        return Err(Error::InvalidParameter {
            what: "elk2 needs 1..=64 key slots",
        });
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::InvalidParameter { what: "elk2 flags" });
    }
    let file_key = FileKey::random(rng);
    let mut base_nonce = [0u8; 12];
    rng(&mut base_nonce[..8]);

    let mut h = Vec::with_capacity(19 + slots.len() * (3 + HYBRID_BODY) + MAC_LEN);
    h.extend_from_slice(MAGIC);
    h.push(cipher.id());
    h.push(flags);
    h.extend_from_slice(&base_nonce);
    h.push(u8::try_from(slots.len()).expect("checked above"));

    for spec in slots {
        let (kind, body) = match spec {
            SlotSpec::Password { password, params } => {
                check_params(params)?;
                let mut salt = [0u8; 16];
                rng(&mut salt);
                let mut kek = argon2::hash(
                    password,
                    &salt,
                    Params {
                        out_len: 32,
                        ..*params
                    },
                )?;
                let wrapped = wrap(&kek, SLOT_PASSWORD, &file_key);
                kek.zeroize();
                let mut body = Vec::with_capacity(PASSWORD_BODY);
                body.extend_from_slice(&params.m_cost.to_le_bytes());
                body.extend_from_slice(&params.t_cost.to_le_bytes());
                body.extend_from_slice(&params.parallelism.to_le_bytes());
                body.extend_from_slice(&salt);
                body.extend_from_slice(&wrapped?);
                (SLOT_PASSWORD, body)
            }
            SlotSpec::Recipient(r) => {
                let mut eph = [0u8; 32];
                rng(&mut eph);
                let eph_pub = x25519_base(&eph);
                let mut ss_x = x25519(&eph, &r.x25519);
                eph.zeroize();
                if ss_x == [0u8; 32] {
                    return Err(Error::InvalidParameter {
                        what: "recipient x25519 key (low-order point)",
                    });
                }
                let (mut ss_k, ct) = mlkem::encaps(&MlKem768, &r.mlkem_ek, &mut *rng)?;
                let mut kek = hybrid_kek(&ss_x, &ss_k, &eph_pub, &r.x25519, &ct);
                ss_x.zeroize();
                ss_k.zeroize();
                let wrapped = wrap(&kek, SLOT_HYBRID, &file_key);
                kek.zeroize();
                let mut body = Vec::with_capacity(HYBRID_BODY);
                body.extend_from_slice(&eph_pub);
                body.extend_from_slice(&ct);
                body.extend_from_slice(&wrapped?);
                (SLOT_HYBRID, body)
            }
        };
        h.push(kind);
        h.extend_from_slice(
            &u16::try_from(body.len())
                .expect("slot bodies are small")
                .to_le_bytes(),
        );
        h.extend_from_slice(&body);
    }
    let mac = file_key.header_mac(&h);
    h.extend_from_slice(&mac);
    Ok(Built {
        header: h,
        file_key,
        base_nonce,
    })
}

// ------------------------------------------------------------------- parsing

/// A parsed key slot.
#[derive(Debug, Clone)]
pub enum Slot {
    /// Password slot.
    Password {
        /// Argon2id cost.
        params: Params,
        /// Argon2 salt.
        salt: [u8; 16],
        /// Wrapped file key.
        wrapped: [u8; WRAPPED_LEN],
    },
    /// X25519 + ML-KEM-768 recipient slot.
    Hybrid {
        /// Ephemeral X25519 public key.
        eph_pub: [u8; 32],
        /// ML-KEM-768 ciphertext.
        ct: Vec<u8>,
        /// Wrapped file key.
        wrapped: [u8; WRAPPED_LEN],
    },
    /// A slot type this version doesn't understand (skipped, but still MAC'd).
    Unknown(u8),
}

/// A parsed ELK2 header.
#[derive(Debug, Clone)]
pub struct Header {
    /// Payload cipher.
    pub cipher: Cipher,
    /// Header flags (`FLAG_ARCHIVE`, …).
    pub flags: u8,
    /// Base nonce for the payload chunks.
    pub base_nonce: [u8; 12],
    /// Key slots, in order.
    pub slots: Vec<Slot>,
    /// Raw header bytes, excluding the MAC.
    bytes: Vec<u8>,
    mac: [u8; MAC_LEN],
}

/// How to try to open a file.
#[derive(Debug, Clone, Copy)]
pub enum Credential<'a> {
    /// A password.
    Password(&'a [u8]),
    /// A secret identity.
    Identity(&'a Identity),
}

impl Header {
    /// Read the rest of a header whose 4-byte magic has already been consumed.
    /// `read_exact` must fill the whole buffer or fail.
    pub fn read_after_magic(read_exact: &mut impl FnMut(&mut [u8]) -> Result<()>) -> Result<Self> {
        let bad = |scheme| Error::InvalidEncoding { scheme };
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        let mut fixed = [0u8; 15];
        read_exact(&mut fixed)?;
        bytes.extend_from_slice(&fixed);
        let cipher = Cipher::from_id(fixed[0])?;
        let flags = fixed[1];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::Unsupported {
                what: "elk2 header flags from a newer easylock",
            });
        }
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&fixed[2..14]);
        let count = usize::from(fixed[14]);
        if count == 0 || count > MAX_SLOTS {
            return Err(bad("elk2 slot count"));
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let mut th = [0u8; 3];
            read_exact(&mut th)?;
            bytes.extend_from_slice(&th);
            let kind = th[0];
            let len = usize::from(u16::from_le_bytes([th[1], th[2]]));
            let mut body = alloc::vec![0u8; len];
            read_exact(&mut body)?;
            bytes.extend_from_slice(&body);
            slots.push(match kind {
                SLOT_PASSWORD => {
                    if len != PASSWORD_BODY {
                        return Err(bad("elk2 password slot"));
                    }
                    let u = |i: usize| {
                        u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]])
                    };
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&body[12..28]);
                    let mut wrapped = [0u8; WRAPPED_LEN];
                    wrapped.copy_from_slice(&body[28..]);
                    Slot::Password {
                        params: Params {
                            m_cost: u(0),
                            t_cost: u(4),
                            parallelism: u(8),
                            out_len: 32,
                        },
                        salt,
                        wrapped,
                    }
                }
                SLOT_HYBRID => {
                    if len != HYBRID_BODY {
                        return Err(bad("elk2 recipient slot"));
                    }
                    let mut wrapped = [0u8; WRAPPED_LEN];
                    wrapped.copy_from_slice(&body[32 + CT_LEN..]);
                    Slot::Hybrid {
                        eph_pub: to32(&body[..32]),
                        ct: body[32..32 + CT_LEN].to_vec(),
                        wrapped,
                    }
                }
                other => Slot::Unknown(other),
            });
        }
        let mut mac = [0u8; MAC_LEN];
        read_exact(&mut mac)?;
        Ok(Header {
            cipher,
            flags,
            base_nonce,
            slots,
            bytes,
            mac,
        })
    }

    /// Parse a header from the start of `data`; returns it and its total length.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 || &data[..4] != MAGIC {
            return Err(Error::InvalidEncoding {
                scheme: "elk2 (bad magic)",
            });
        }
        let mut pos = 4;
        let h = Self::read_after_magic(&mut |buf: &mut [u8]| {
            let end = pos + buf.len();
            if end > data.len() {
                return Err(Error::InvalidEncoding {
                    scheme: "elk2 header (truncated)",
                });
            }
            buf.copy_from_slice(&data[pos..end]);
            pos = end;
            Ok(())
        })?;
        Ok((h, pos))
    }

    /// Whether the payload is a folder archive.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        self.flags & FLAG_ARCHIVE != 0
    }

    /// Argon2 parameters of every password slot.
    #[must_use]
    pub fn password_slots(&self) -> Vec<Params> {
        self.slots
            .iter()
            .filter_map(|s| match s {
                Slot::Password { params, .. } => Some(*params),
                _ => None,
            })
            .collect()
    }

    /// Number of public-key recipient slots.
    #[must_use]
    pub fn recipient_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, Slot::Hybrid { .. }))
            .count()
    }

    fn mac_ok(&self, fk: &FileKey) -> bool {
        bool::from(ct_eq(&fk.header_mac(&self.bytes), &self.mac))
    }

    /// Recover the file key with any of `creds`. Fails with
    /// [`Error::Authentication`] if no slot opens or the header was tampered with.
    pub fn unlock(&self, creds: &[Credential<'_>]) -> Result<FileKey> {
        for cred in creds {
            for slot in &self.slots {
                let fk = match (cred, slot) {
                    (
                        Credential::Password(pw),
                        Slot::Password {
                            params,
                            salt,
                            wrapped,
                        },
                    ) => {
                        check_params(params)?;
                        let mut kek = argon2::hash(pw, salt, *params)?;
                        let r = unwrap(&kek, SLOT_PASSWORD, wrapped);
                        kek.zeroize();
                        r
                    }
                    (
                        Credential::Identity(id),
                        Slot::Hybrid {
                            eph_pub,
                            ct,
                            wrapped,
                        },
                    ) => id.try_unwrap(eph_pub, ct, wrapped),
                    _ => continue,
                };
                if let Ok(fk) = fk {
                    // A slot opened: the header must now authenticate, or it was tampered with.
                    return if self.mac_ok(&fk) {
                        Ok(fk)
                    } else {
                        Err(Error::Authentication)
                    };
                }
            }
        }
        Err(Error::Authentication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn rng() -> impl FnMut(&mut [u8]) {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        move |b: &mut [u8]| {
            for x in b.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *x = s as u8;
            }
        }
    }

    const FAST: Params = Params {
        m_cost: 64,
        t_cost: 1,
        parallelism: 1,
        out_len: 32,
    };

    #[test]
    fn identity_and_recipient_strings_roundtrip() {
        let id = Identity::generate(&mut rng());
        let s = id.encode_secret();
        assert!(s.starts_with("ELK-SECRET-KEY-1"));
        let id2 = Identity::parse(&s).unwrap();
        assert_eq!(id.recipient(), id2.recipient());
        let pubs = id.recipient().encode();
        assert!(pubs.starts_with("elkpub1"));
        assert_eq!(Recipient::parse(&pubs).unwrap(), id.recipient());
        // a single-character typo is caught by the checksum
        let mut typo = pubs.clone().into_bytes();
        typo[20] = if typo[20] == b'A' { b'B' } else { b'A' };
        assert!(Recipient::parse(core::str::from_utf8(&typo).unwrap()).is_err());
    }

    #[test]
    fn slots_unlock_and_reject() {
        let mut r = rng();
        let alice = Identity::generate(&mut r);
        let bob = Identity::generate(&mut r);
        let eve = Identity::generate(&mut r);
        let (ra, rb) = (alice.recipient(), bob.recipient());
        let built = build(
            Cipher::ChaCha20Poly1305,
            FLAG_ARCHIVE,
            &[
                SlotSpec::Password {
                    password: b"pw",
                    params: FAST,
                },
                SlotSpec::Recipient(&ra),
                SlotSpec::Recipient(&rb),
            ],
            &mut r,
        )
        .unwrap();
        let (h, len) = Header::parse(&built.header).unwrap();
        assert_eq!(len, built.header.len());
        assert!(h.is_archive());
        assert_eq!(h.recipient_slots(), 2);
        let want = built.file_key.0;
        for cred in [
            Credential::Password(b"pw"),
            Credential::Identity(&alice),
            Credential::Identity(&bob),
        ] {
            assert_eq!(h.unlock(&[cred]).unwrap().0, want);
        }
        assert!(h.unlock(&[Credential::Password(b"nope")]).is_err());
        assert!(h.unlock(&[Credential::Identity(&eve)]).is_err());
        assert!(h
            .unlock(&[Credential::Identity(&eve), Credential::Password(b"pw")])
            .is_ok());
    }

    #[test]
    fn header_tamper_is_detected() {
        let built = build(
            Cipher::Aes256Gcm,
            0,
            &[SlotSpec::Password {
                password: b"pw",
                params: FAST,
            }],
            &mut rng(),
        )
        .unwrap();
        // flipping the archive flag, the cipher or the nonce breaks the MAC
        for i in [4usize, 5, 10] {
            let mut bad = built.header.clone();
            bad[i] ^= 1;
            if let Ok((h, _)) = Header::parse(&bad) {
                assert!(
                    h.unlock(&[Credential::Password(b"pw")]).is_err(),
                    "byte {i}"
                );
            }
        }
    }

    #[test]
    fn hostile_argon_params_are_refused() {
        let mut built = build(
            Cipher::Aes256Gcm,
            0,
            &[SlotSpec::Password {
                password: b"pw",
                params: FAST,
            }],
            &mut rng(),
        )
        .unwrap();
        // m_cost field of the first slot starts at 19 + 3
        built.header[22..26].copy_from_slice(&u32::MAX.to_le_bytes());
        let (h, _) = Header::parse(&built.header).unwrap();
        assert!(matches!(
            h.unlock(&[Credential::Password(b"pw")]),
            Err(Error::InvalidParameter { .. })
        ));
    }
}
