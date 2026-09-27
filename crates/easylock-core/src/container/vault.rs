//! **Encrypted vaults** (`std` only): a directory where files *stay* encrypted at rest.
//! You add, list, read and remove them without ever writing plaintext to disk, and
//! even file names and sizes are hidden inside the encrypted index.
//!
//! ```text
//! VAULT/
//!   vault.elk              ELK2 file (password and/or public-key slots) whose payload is
//!                          "ELKVAULT" ‖ version u8 ‖ cipher u8 ‖ master_key[32]
//!   index                  "ELKI" ‖ nonce[12] ‖ AEAD(k_index, nonce, "elkvault index v1", index)
//!   objects/ab/<32 hex>    "ELKO" ‖ base_nonce[12] ‖ chunk stream under
//!                          HKDF(master, salt = object id, "elkvault object")
//!   .lock                  present while a process modifies the vault
//! ```
//!
//! Because every object key is derived from its random id, objects can't be swapped
//! between entries. Changing the password or recipients only rewrites `vault.elk`.
//! **Limitation:** an attacker with write access could roll the whole vault back to an
//! older state (as with any offline encrypted store without a trusted counter).

use super::elk2::{Credential, SlotSpec};
use super::stream::{self, io_error, Decryptor, EncryptOptions, Encryptor};
use super::{archive, Cipher};
use crate::aead::{Aead, ChaCha20Poly1305};
use crate::encode::hex;
use crate::hash::Sha256;
use crate::kdf::Hkdf;
use crate::secure::Zeroize;
use crate::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const VAULT_MAGIC: &[u8; 8] = b"ELKVAULT";
const VAULT_VERSION: u8 = 1;
const INDEX_MAGIC: &[u8; 4] = b"ELKI";
const OBJECT_MAGIC: &[u8; 4] = b"ELKO";
const INDEX_AAD: &[u8] = b"elkvault index v1";

/// File name of the vault's key file inside the vault directory.
pub const KEY_FILE: &str = "vault.elk";

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn derive(master: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut v = Hkdf::<Sha256>::derive(salt, master, info, 32).expect("valid HKDF length");
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    v.zeroize();
    k
}

/// One file stored in a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `/`-separated path inside the vault.
    pub path: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Original modification time (unix seconds).
    pub mtime: i64,
    /// Unix permission bits.
    pub mode: u32,
    /// When it was added (unix seconds).
    pub added: i64,
    id: [u8; 16],
}

impl Entry {
    fn object_rel(&self) -> PathBuf {
        let h = hex::encode(&self.id);
        PathBuf::from("objects").join(&h[..2]).join(&h)
    }
}

/// Holds `.lock` while alive.
#[derive(Debug)]
struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// An opened vault.
pub struct Vault {
    dir: PathBuf,
    master: [u8; 32],
    cipher: Cipher,
    entries: Vec<Entry>,
    generation: u64,
    trash: Vec<PathBuf>,
    lock: Option<LockGuard>,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.dir)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Write `data` to `path` atomically (temp file, fsync, rename).
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn validate_path(p: &str) -> io::Result<String> {
    let clean = p.trim_matches('/').to_string();
    archive::safe_relative(&clean)?;
    Ok(clean)
}

impl Vault {
    /// Create a new, empty vault in `dir` (which must not exist or be empty).
    pub fn create(
        dir: &Path,
        cipher: Cipher,
        slots: &[SlotSpec<'_>],
        rng: &mut impl FnMut(&mut [u8]),
    ) -> io::Result<Vault> {
        if dir.exists() && fs::read_dir(dir)?.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "directory is not empty",
            ));
        }
        fs::create_dir_all(dir.join("objects"))?;
        let mut master = [0u8; 32];
        rng(&mut master);
        let v = Vault {
            dir: dir.to_path_buf(),
            master,
            cipher,
            entries: Vec::new(),
            generation: 0,
            trash: Vec::new(),
            lock: None,
        };
        v.write_key_file(slots, rng)?;
        let mut v = v;
        v.lock()?;
        v.save(rng)?;
        Ok(v)
    }

    /// How `vault.elk` can be unlocked (no secrets needed).
    pub fn info(dir: &Path) -> io::Result<stream::Info> {
        stream::inspect(BufReader::new(File::open(dir.join(KEY_FILE))?))
    }

    /// Open an existing vault with any of `creds` (read-only until [`Vault::lock`]).
    pub fn open(dir: &Path, creds: &[Credential<'_>]) -> io::Result<Vault> {
        let (mut dec, _) = stream::decrypt(BufReader::new(File::open(dir.join(KEY_FILE))?), creds)?;
        let mut payload = Vec::new();
        dec.read_to_end(&mut payload)?;
        if payload.len() != 8 + 2 + 32
            || &payload[..8] != VAULT_MAGIC
            || payload[8] != VAULT_VERSION
        {
            payload.zeroize();
            return Err(invalid("not an easylock vault (or an unsupported version)"));
        }
        let cipher = Cipher::from_id(payload[9]).map_err(io_error)?;
        let mut master = [0u8; 32];
        master.copy_from_slice(&payload[10..]);
        payload.zeroize();
        let mut v = Vault {
            dir: dir.to_path_buf(),
            master,
            cipher,
            entries: Vec::new(),
            generation: 0,
            trash: Vec::new(),
            lock: None,
        };
        v.load_index()?;
        Ok(v)
    }

    /// Take the write lock and re-read the index (call before modifying).
    pub fn lock(&mut self) -> io::Result<()> {
        if self.lock.is_some() {
            return Ok(());
        }
        let path = self.dir.join(".lock");
        let mut f = OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("vault is in use by another process (delete {} if that process crashed)", path.display()),
                )
            } else {
                e
            }
        })?;
        let _ = write!(f, "{}", std::process::id());
        self.lock = Some(LockGuard(path));
        if self.dir.join("index").exists() {
            self.load_index()?;
        }
        Ok(())
    }

    fn write_key_file(
        &self,
        slots: &[SlotSpec<'_>],
        rng: &mut impl FnMut(&mut [u8]),
    ) -> io::Result<()> {
        let mut payload = Vec::with_capacity(42);
        payload.extend_from_slice(VAULT_MAGIC);
        payload.push(VAULT_VERSION);
        payload.push(self.cipher.id());
        payload.extend_from_slice(&self.master);
        let opts = EncryptOptions {
            cipher: Cipher::ChaCha20Poly1305,
            slots: slots.to_vec(),
            flags: 0,
        };
        let sealed = stream::seal_bytes(&payload, &opts, rng).map_err(io_error);
        payload.zeroize();
        write_atomic(&self.dir.join(KEY_FILE), &sealed?)
    }

    /// Replace the password / recipients that unlock the vault. The master key and
    /// all stored files stay the same.
    pub fn rekey(
        &mut self,
        slots: &[SlotSpec<'_>],
        rng: &mut impl FnMut(&mut [u8]),
    ) -> io::Result<()> {
        self.lock()?;
        self.write_key_file(slots, rng)
    }

    fn load_index(&mut self) -> io::Result<()> {
        let data = fs::read(self.dir.join("index"))?;
        if data.len() < 4 + 12 + 16 || &data[..4] != INDEX_MAGIC {
            return Err(invalid("vault index is missing or damaged"));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[4..16]);
        let mut k = derive(&self.master, &[], b"elkvault index");
        let opened = ChaCha20Poly1305::new(&k).and_then(|c| c.open(&nonce, INDEX_AAD, &data[16..]));
        k.zeroize();
        let mut plain = opened.map_err(|_| io_error(Error::Authentication))?;
        let parsed = parse_index(&plain);
        plain.zeroize();
        let (generation, entries) = parsed?;
        self.generation = generation;
        self.entries = entries;
        Ok(())
    }

    /// Write the index atomically, then delete objects that are no longer referenced.
    pub fn save(&mut self, rng: &mut impl FnMut(&mut [u8])) -> io::Result<()> {
        self.lock()?;
        self.generation += 1;
        let mut plain = Vec::with_capacity(64 + self.entries.len() * 96);
        plain.extend_from_slice(&self.generation.to_le_bytes());
        plain.extend_from_slice(
            &u32::try_from(self.entries.len())
                .map_err(|_| invalid("too many entries"))?
                .to_le_bytes(),
        );
        for e in &self.entries {
            let len = u16::try_from(e.path.len()).map_err(|_| invalid("path too long"))?;
            plain.extend_from_slice(&len.to_le_bytes());
            plain.extend_from_slice(e.path.as_bytes());
            plain.extend_from_slice(&e.id);
            plain.extend_from_slice(&e.size.to_le_bytes());
            plain.extend_from_slice(&e.mtime.to_le_bytes());
            plain.extend_from_slice(&e.mode.to_le_bytes());
            plain.extend_from_slice(&e.added.to_le_bytes());
        }
        let mut nonce = [0u8; 12];
        rng(&mut nonce);
        let mut k = derive(&self.master, &[], b"elkvault index");
        let sealed = ChaCha20Poly1305::new(&k).map(|c| c.seal(&nonce, INDEX_AAD, &plain));
        k.zeroize();
        plain.zeroize();
        let mut out = Vec::with_capacity(16 + plain.len() + 16);
        out.extend_from_slice(INDEX_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed.map_err(io_error)?);
        write_atomic(&self.dir.join("index"), &out)?;
        for p in self.trash.drain(..) {
            let _ = fs::remove_file(&p);
        }
        Ok(())
    }

    /// All entries, sorted by path.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The vault's payload cipher.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Entries at `prefix` exactly, or inside the folder `prefix/`.
    #[must_use]
    pub fn find(&self, prefix: &str) -> Vec<&Entry> {
        let p = prefix.trim_matches('/');
        self.entries
            .iter()
            .filter(|e| p.is_empty() || e.path == p || e.path.starts_with(&format!("{p}/")))
            .collect()
    }

    fn object_key(&self, id: &[u8; 16]) -> [u8; 32] {
        derive(&self.master, id, b"elkvault object")
    }

    /// Encrypt everything from `r` and store it as `path` (replacing an existing entry).
    /// Call [`Vault::save`] afterwards to commit.
    pub fn add(
        &mut self,
        path: &str,
        r: &mut impl Read,
        mtime: i64,
        mode: u32,
        rng: &mut impl FnMut(&mut [u8]),
    ) -> io::Result<u64> {
        self.lock()?;
        let path = validate_path(path)?;
        let mut id = [0u8; 16];
        rng(&mut id);
        let mut base = [0u8; 12];
        rng(&mut base[..8]);
        let entry = Entry {
            path,
            size: 0,
            mtime,
            mode: mode & 0o777,
            added: now(),
            id,
        };
        let dest = self.dir.join(entry.object_rel());
        fs::create_dir_all(dest.parent().expect("object path has a parent"))?;
        let tmp = dest.with_extension("part");
        let size = (|| -> io::Result<u64> {
            let mut f = BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
            f.write_all(OBJECT_MAGIC)?;
            f.write_all(&base)?;
            let mut key = self.object_key(&id);
            let enc = Encryptor::with_key(f, self.cipher, &key, base).map_err(io_error);
            key.zeroize();
            let mut enc = enc?;
            let n = io::copy(r, &mut enc)?;
            let f = enc.finish()?;
            f.into_inner()
                .map_err(io::IntoInnerError::into_error)?
                .sync_all()?;
            Ok(n)
        })();
        let size = match size {
            Ok(n) => n,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        fs::rename(&tmp, &dest)?;
        let entry = Entry { size, ..entry };
        if let Some(pos) = self.entries.iter().position(|e| e.path == entry.path) {
            let old = std::mem::replace(&mut self.entries[pos], entry);
            self.trash.push(self.dir.join(old.object_rel()));
        } else {
            let pos = self.entries.partition_point(|e| e.path < entry.path);
            self.entries.insert(pos, entry);
        }
        Ok(size)
    }

    /// Stream the plaintext of `path`.
    pub fn read(&self, path: &str) -> io::Result<Decryptor<BufReader<File>>> {
        let e = self
            .entries
            .iter()
            .find(|e| e.path == path.trim_matches('/'))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("not in vault: {path}"))
            })?;
        let mut f = BufReader::with_capacity(1 << 20, File::open(self.dir.join(e.object_rel()))?);
        let mut head = [0u8; 16];
        f.read_exact(&mut head)?;
        if &head[..4] != OBJECT_MAGIC {
            return Err(invalid("vault object damaged"));
        }
        let mut base = [0u8; 12];
        base.copy_from_slice(&head[4..]);
        let mut key = self.object_key(&e.id);
        let d = Decryptor::with_key(f, self.cipher, &key, base).map_err(io_error);
        key.zeroize();
        d
    }

    /// Remove `path` (or everything under the folder `path/`). Returns how many
    /// entries were removed. Call [`Vault::save`] afterwards to commit.
    pub fn remove(&mut self, path: &str) -> io::Result<usize> {
        self.lock()?;
        let p = path.trim_matches('/').to_string();
        let before = self.entries.len();
        let mut keep = Vec::with_capacity(before);
        for e in self.entries.drain(..) {
            if e.path == p || e.path.starts_with(&format!("{p}/")) {
                self.trash.push(self.dir.join(e.object_rel()));
            } else {
                keep.push(e);
            }
        }
        self.entries = keep;
        Ok(before - self.entries.len())
    }
}

fn parse_index(b: &[u8]) -> io::Result<(u64, Vec<Entry>)> {
    let bad = || invalid("vault index is malformed");
    let mut pos = 0usize;
    let mut take = |n: usize| -> io::Result<&[u8]> {
        let s = b.get(pos..pos + n).ok_or_else(bad)?;
        pos += n;
        Ok(s)
    };
    let generation = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
    let count = u32::from_le_bytes(take(4)?.try_into().expect("4 bytes"));
    let mut entries = Vec::with_capacity(count.min(1 << 16) as usize);
    for _ in 0..count {
        let len = usize::from(u16::from_le_bytes(take(2)?.try_into().expect("2 bytes")));
        let path = String::from_utf8(take(len)?.to_vec()).map_err(|_| bad())?;
        archive::safe_relative(&path)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(take(16)?);
        let size = u64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
        let mtime = i64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
        let mode = u32::from_le_bytes(take(4)?.try_into().expect("4 bytes"));
        let added = i64::from_le_bytes(take(8)?.try_into().expect("8 bytes"));
        entries.push(Entry {
            path,
            size,
            mtime,
            mode,
            added,
            id,
        });
    }
    Ok((generation, entries))
}

#[cfg(test)]
mod tests {
    use super::super::elk2::Identity;
    use super::*;
    use crate::kdf::argon2::Params;

    fn rng() -> impl FnMut(&mut [u8]) {
        let mut s = 0x0123_4567_89ab_cdefu64;
        move |b: &mut [u8]| {
            for x in b.iter_mut() {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *x = (s >> 56) as u8;
            }
        }
    }
    const FAST: Params = Params {
        m_cost: 64,
        t_cost: 1,
        parallelism: 1,
        out_len: 32,
    };

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("easylock-vault-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn read_all(v: &Vault, p: &str) -> Vec<u8> {
        let mut out = Vec::new();
        v.read(p).unwrap().read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn add_list_read_replace_remove_rekey() {
        let dir = tmp("basic");
        let mut r = rng();
        let pw = [SlotSpec::Password {
            password: b"pw",
            params: FAST,
        }];
        let mut v = Vault::create(&dir, Cipher::ChaCha20Poly1305, &pw, &mut r).unwrap();
        let big: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
        v.add("docs/big.bin", &mut &big[..], 1, 0o644, &mut r)
            .unwrap();
        v.add("notes.txt", &mut &b"secret notes"[..], 2, 0o600, &mut r)
            .unwrap();
        v.save(&mut r).unwrap();
        drop(v);

        // Nothing in the vault directory reveals file names or contents.
        for e in walk(&dir) {
            let bytes = fs::read(&e).unwrap();
            assert!(
                !contains(&bytes, b"notes.txt") && !contains(&bytes, b"secret notes"),
                "{e:?}"
            );
        }

        let mut v = Vault::open(&dir, &[Credential::Password(b"pw")]).unwrap();
        assert_eq!(
            v.entries()
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["docs/big.bin", "notes.txt"]
        );
        assert_eq!(read_all(&v, "docs/big.bin"), big);
        assert_eq!(v.find("docs").len(), 1);

        v.add("notes.txt", &mut &b"v2"[..], 3, 0o600, &mut r)
            .unwrap();
        assert_eq!(v.remove("docs").unwrap(), 1);
        v.save(&mut r).unwrap();
        assert_eq!(read_all(&v, "notes.txt"), b"v2");
        assert_eq!(
            walk(&dir.join("objects")).len(),
            1,
            "old objects are deleted"
        );

        let id = Identity::generate(&mut r);
        let rec = id.recipient();
        v.rekey(&[SlotSpec::Recipient(&rec)], &mut r).unwrap();
        drop(v);
        assert!(Vault::open(&dir, &[Credential::Password(b"pw")]).is_err());
        let v = Vault::open(&dir, &[Credential::Identity(&id)]).unwrap();
        assert_eq!(read_all(&v, "notes.txt"), b"v2");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampering_and_hostile_paths_fail() {
        let dir = tmp("tamper");
        let mut r = rng();
        let pw = [SlotSpec::Password {
            password: b"pw",
            params: FAST,
        }];
        let mut v = Vault::create(&dir, Cipher::Aes256Gcm, &pw, &mut r).unwrap();
        assert!(v.add("../escape", &mut &b"x"[..], 0, 0, &mut r).is_err());
        v.add("a", &mut &b"aaaa"[..], 0, 0, &mut r).unwrap();
        v.add("b", &mut &b"bbbb"[..], 0, 0, &mut r).unwrap();
        v.save(&mut r).unwrap();
        // swap the two object files: keys are bound to ids, so both reads fail
        let objs = walk(&dir.join("objects"));
        let (a, b) = (fs::read(&objs[0]).unwrap(), fs::read(&objs[1]).unwrap());
        fs::write(&objs[0], &b).unwrap();
        fs::write(&objs[1], &a).unwrap();
        let mut out = Vec::new();
        assert!(v.read("a").unwrap().read_to_end(&mut out).is_err());
        // a flipped index byte is detected
        drop(v);
        let mut idx = fs::read(dir.join("index")).unwrap();
        let last = idx.len() - 1;
        idx[last] ^= 1;
        fs::write(dir.join("index"), idx).unwrap();
        assert!(Vault::open(&dir, &[Credential::Password(b"pw")]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = tmp("lock");
        let mut r = rng();
        let pw = [SlotSpec::Password {
            password: b"pw",
            params: FAST,
        }];
        let v = Vault::create(&dir, Cipher::Aes256Gcm, &pw, &mut r).unwrap();
        let mut other = Vault::open(&dir, &[Credential::Password(b"pw")]).unwrap();
        assert!(other.lock().is_err());
        drop(v);
        assert!(other.lock().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    fn walk(d: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in fs::read_dir(d).unwrap().flatten() {
            if e.path().is_dir() {
                out.extend(walk(&e.path()));
            } else {
                out.push(e.path());
            }
        }
        out.sort();
        out
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }
}
