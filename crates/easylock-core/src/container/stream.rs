//! Streaming, multi-core encryption and decryption of `.elk` files (`std` only).
//!
//! * [`Encryptor`] is a [`Write`] sink: bytes written to it come out as sealed
//!   256 KiB chunks. Memory use is bounded (a few MiB) no matter how large the input is.
//! * [`Decryptor`] is a [`Read`] source that authenticates every chunk before
//!   releasing it and fails on truncation or trailing data.
//!
//! Chunks are independent, so batches of them are sealed / opened in parallel on
//! all available cores with `std::thread::scope` (no dependencies, no thread pool).
//! On targets without threads (e.g. `wasm32`) everything runs on the calling thread.

use super::elk2::{self, Credential, Header, SlotSpec};
use super::{chunk_aad, chunk_nonce, Cipher, CHUNK};
use crate::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use crate::kdf::argon2;
use crate::secure::Zeroize;
use crate::{Error, Result};
use std::io::{self, Read, Write};
use std::sync::Arc;

const TAG: usize = 16;
const MAX_SEALED: usize = CHUNK + TAG;

/// Wrap a core error as an `io::Error` (kind `InvalidData`).
#[must_use]
pub fn io_error(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Recover the core [`Error`] carried by an `io::Error`, if any.
#[must_use]
pub fn core_error(e: &io::Error) -> Option<&Error> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<Error>())
}

/// Worker threads used for chunk processing.
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(16)
}

/// A keyed AEAD instance shared (read-only) across worker threads.
#[allow(clippy::large_enum_variant)] // one instance per file, behind an Arc
enum Keyed {
    Aes(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl Keyed {
    fn new(cipher: Cipher, key: &[u8; 32]) -> Result<Self> {
        Ok(match cipher {
            Cipher::Aes256Gcm => Keyed::Aes(Aes256Gcm::new(key)?),
            Cipher::ChaCha20Poly1305 => Keyed::ChaCha(ChaCha20Poly1305::new(key)?),
        })
    }
    fn seal(&self, n: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        match self {
            Keyed::Aes(c) => c.seal(n, aad, pt),
            Keyed::ChaCha(c) => c.seal(n, aad, pt),
        }
    }
    fn open(&self, n: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        match self {
            Keyed::Aes(c) => c.open(n, aad, ct),
            Keyed::ChaCha(c) => c.open(n, aad, ct),
        }
    }
}

fn chunk_index(counter: u64) -> io::Result<u32> {
    u32::try_from(counter).map_err(|_| io_error(Error::CounterExhausted))
}

#[derive(Clone, Copy)]
enum Mode {
    Seal,
    Open,
}

/// A batch of chunks being sealed or opened, possibly still running on worker
/// threads. Waiting on it yields the results in order.
enum Batch {
    Done(Vec<Result<Vec<u8>>>),
    Running(Vec<std::thread::JoinHandle<Vec<Result<Vec<u8>>>>>),
}

impl Batch {
    /// Start processing `items` (chunk indices `first..`). When `ends_file` is set the
    /// last item is the final chunk of the file.
    fn start(
        keyed: &Arc<Keyed>,
        base: [u8; 12],
        first: u32,
        items: Vec<Vec<u8>>,
        ends_file: bool,
        mode: Mode,
        threads: usize,
    ) -> Self {
        let n = items.len();
        let work =
            move |keyed: &Keyed, offset: usize, group: Vec<Vec<u8>>| -> Vec<Result<Vec<u8>>> {
                group
                    .into_iter()
                    .enumerate()
                    .map(|(k, mut data)| {
                        let pos = offset + k;
                        // `first + pos` was range-checked by the caller.
                        let i = first + u32::try_from(pos).expect("batch index fits u32");
                        let (nonce, aad) = (
                            chunk_nonce(&base, i),
                            chunk_aad(i, ends_file && pos == n - 1),
                        );
                        let r = match mode {
                            Mode::Seal => Ok(keyed.seal(&nonce, &aad, &data)),
                            Mode::Open => keyed.open(&nonce, &aad, &data),
                        };
                        data.zeroize();
                        r
                    })
                    .collect()
            };
        if threads <= 1 || n <= 1 {
            return Batch::Done(work(keyed, 0, items));
        }
        let per = n.div_ceil(threads);
        let mut handles = Vec::with_capacity(threads);
        let mut rest = items.into_iter();
        let mut offset = 0;
        while offset < n {
            let group: Vec<Vec<u8>> = rest.by_ref().take(per).collect();
            let len = group.len();
            let k = Arc::clone(keyed);
            handles.push(std::thread::spawn(move || work(&k, offset, group)));
            offset += len;
        }
        Batch::Running(handles)
    }

    fn wait(self) -> Vec<Result<Vec<u8>>> {
        match self {
            Batch::Done(v) => v,
            Batch::Running(hs) => hs
                .into_iter()
                .flat_map(|h| h.join().expect("easylock worker thread panicked"))
                .collect(),
        }
    }
}

// ------------------------------------------------------------------ encryptor

/// Streaming encryptor. Write plaintext into it, then call [`Encryptor::finish`].
/// Dropping it without `finish` produces an incomplete (undecryptable) file.
///
/// Sealing runs on worker threads while the caller keeps reading input and the
/// previous batch is written out (a three-stage pipeline).
pub struct Encryptor<W: Write> {
    inner: Option<W>,
    keyed: Arc<Keyed>,
    base_nonce: [u8; 12],
    counter: u64,
    pending: Vec<u8>,
    batch: Vec<Vec<u8>>,
    inflight: Option<Batch>,
    threads: usize,
    batch_cap: usize,
}

impl<W: Write> Encryptor<W> {
    fn new(inner: W, cipher: Cipher, key: &[u8; 32], base_nonce: [u8; 12]) -> Result<Self> {
        let threads = worker_count();
        Ok(Encryptor {
            inner: Some(inner),
            keyed: Arc::new(Keyed::new(cipher, key)?),
            base_nonce,
            counter: 0,
            pending: Vec::with_capacity(CHUNK),
            batch: Vec::new(),
            inflight: None,
            threads,
            batch_cap: if threads > 1 { threads * 4 } else { 1 },
        })
    }

    fn write_out(&mut self, done: Batch) -> io::Result<()> {
        let sealed = done.wait();
        let mut out = Vec::with_capacity(
            sealed
                .iter()
                .map(|c| c.as_ref().map_or(0, Vec::len) + 4)
                .sum(),
        );
        for c in sealed {
            let c = c.map_err(io_error)?;
            out.extend_from_slice(
                &u32::try_from(c.len())
                    .expect("chunk fits u32")
                    .to_le_bytes(),
            );
            out.extend_from_slice(&c);
        }
        self.inner
            .as_mut()
            .expect("writer present until finish")
            .write_all(&out)
    }

    fn flush_batch(&mut self, ends_file: bool) -> io::Result<()> {
        let items = std::mem::take(&mut self.batch);
        let n = items.len() as u64;
        if n > 0 {
            chunk_index(self.counter + n - 1)?;
            let first = chunk_index(self.counter)?;
            let job = Batch::start(
                &self.keyed,
                self.base_nonce,
                first,
                items,
                ends_file,
                Mode::Seal,
                self.threads,
            );
            self.counter += n;
            if let Some(prev) = self.inflight.replace(job) {
                self.write_out(prev)?; // overlaps with sealing the new batch
            }
        }
        if ends_file {
            if let Some(last) = self.inflight.take() {
                self.write_out(last)?;
            }
        }
        Ok(())
    }

    /// Seal the final chunk, flush, and return the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        let tail = std::mem::take(&mut self.pending);
        if tail.len() == CHUNK {
            // A full chunk is never "last": terminate with an empty final chunk.
            self.batch.push(tail);
            self.batch.push(Vec::new());
        } else {
            self.batch.push(tail);
        }
        self.flush_batch(true)?;
        let mut inner = self.inner.take().expect("writer present until finish");
        inner.flush()?;
        Ok(inner)
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let total = buf.len();
        while !buf.is_empty() {
            if self.pending.len() == CHUNK {
                // More data follows, so this full chunk is not the last one.
                let full = std::mem::replace(&mut self.pending, Vec::with_capacity(CHUNK));
                self.batch.push(full);
                if self.batch.len() >= self.batch_cap {
                    self.flush_batch(false)?;
                }
            }
            let n = (CHUNK - self.pending.len()).min(buf.len());
            self.pending.extend_from_slice(&buf[..n]);
            buf = &buf[n..];
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Chunks can only be sealed once we know whether they are last; nothing to do.
        Ok(())
    }
}

impl<W: Write> Drop for Encryptor<W> {
    fn drop(&mut self) {
        self.pending.zeroize();
        for b in &mut self.batch {
            b.zeroize();
        }
    }
}

impl<W: Write> core::fmt::Debug for Encryptor<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryptor")
            .field("chunks", &self.counter)
            .finish_non_exhaustive()
    }
}

/// What to put in a new file.
#[derive(Debug, Clone)]
pub struct EncryptOptions<'a> {
    /// Payload cipher.
    pub cipher: Cipher,
    /// Key slots (at least one).
    pub slots: Vec<SlotSpec<'a>>,
    /// Header flags (e.g. [`elk2::FLAG_ARCHIVE`]).
    pub flags: u8,
}

/// Write an ELK2 header to `w` and return an [`Encryptor`] for the payload.
///
/// `rng` must fill buffers with cryptographically secure randomness.
pub fn encrypt<W: Write>(
    mut w: W,
    opts: &EncryptOptions<'_>,
    rng: &mut impl FnMut(&mut [u8]),
) -> io::Result<Encryptor<W>> {
    let built = elk2::build(opts.cipher, opts.flags, &opts.slots, rng).map_err(io_error)?;
    w.write_all(&built.header)?;
    let mut key = built.file_key.payload_key(&built.base_nonce);
    let enc = Encryptor::new(w, opts.cipher, &key, built.base_nonce).map_err(io_error);
    key.zeroize();
    enc
}

// ------------------------------------------------------------------ decryptor

/// Streaming decryptor: a [`Read`] of authenticated plaintext. The next batch is
/// read and decrypted on worker threads while the caller consumes the current one.
pub struct Decryptor<R: Read> {
    inner: R,
    keyed: Arc<Keyed>,
    base_nonce: [u8; 12],
    counter: u64,
    out: Vec<u8>,
    pos: usize,
    inflight: Option<(Batch, bool)>,
    input_done: bool,
    done: bool,
    threads: usize,
    batch_cap: usize,
}

impl<R: Read> Decryptor<R> {
    fn new(inner: R, cipher: Cipher, key: &[u8; 32], base_nonce: [u8; 12]) -> Result<Self> {
        let threads = worker_count();
        Ok(Decryptor {
            inner,
            keyed: Arc::new(Keyed::new(cipher, key)?),
            base_nonce,
            counter: 0,
            out: Vec::new(),
            pos: 0,
            inflight: None,
            input_done: false,
            done: false,
            threads,
            batch_cap: if threads > 1 { threads * 4 } else { 1 },
        })
    }

    /// Read the next batch of sealed chunks and start opening it.
    fn start_next(&mut self) -> io::Result<()> {
        let truncated = || io_error(Error::Authentication);
        let mut sealed: Vec<Vec<u8>> = Vec::with_capacity(self.batch_cap);
        let mut saw_last = false;
        while sealed.len() < self.batch_cap {
            let mut len = [0u8; 4];
            self.inner.read_exact(&mut len).map_err(|_| truncated())?;
            let len = u32::from_le_bytes(len) as usize;
            if !(TAG..=MAX_SEALED).contains(&len) {
                return Err(io_error(Error::InvalidEncoding {
                    scheme: "elk chunk length",
                }));
            }
            let mut c = vec![0u8; len];
            self.inner.read_exact(&mut c).map_err(|_| truncated())?;
            sealed.push(c);
            if len < MAX_SEALED {
                saw_last = true;
                let mut probe = [0u8; 1];
                if self.inner.read(&mut probe)? != 0 {
                    return Err(io_error(Error::Authentication)); // data after the final chunk
                }
                break;
            }
        }
        let n = sealed.len() as u64;
        chunk_index(self.counter + n - 1)?;
        let first = chunk_index(self.counter)?;
        let job = Batch::start(
            &self.keyed,
            self.base_nonce,
            first,
            sealed,
            saw_last,
            Mode::Open,
            self.threads,
        );
        self.counter += n;
        self.input_done = saw_last;
        self.inflight = Some((job, saw_last));
        Ok(())
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.inflight.is_none() {
            self.start_next()?;
        }
        let (job, is_last) = self.inflight.take().expect("a batch is in flight");
        if !self.input_done {
            self.start_next()?; // read ahead while this batch is being opened
        }
        self.out.zeroize();
        self.out.clear();
        self.pos = 0;
        for r in job.wait() {
            let mut pt = r.map_err(io_error)?;
            self.out.extend_from_slice(&pt);
            pt.zeroize();
        }
        self.done = is_last;
        Ok(())
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.out.len() {
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            self.fill()?;
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<R: Read> Drop for Decryptor<R> {
    fn drop(&mut self) {
        self.out.zeroize();
        if let Some((job, _)) = self.inflight.take() {
            for mut r in job.wait().into_iter().flatten() {
                r.zeroize();
            }
        }
    }
}

impl<R: Read> core::fmt::Debug for Decryptor<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Decryptor")
            .field("chunks", &self.counter)
            .finish_non_exhaustive()
    }
}

/// Public facts about an encrypted file (readable without any key).
#[derive(Debug, Clone)]
pub struct Info {
    /// Format version: 1 (`ELK1`) or 2 (`ELK2`).
    pub version: u8,
    /// Payload cipher.
    pub cipher: Cipher,
    /// Whether the payload is a folder archive.
    pub archive: bool,
    /// Argon2 parameters of each password slot.
    pub password_slots: Vec<argon2::Params>,
    /// Number of public-key recipients.
    pub recipients: usize,
}

enum Parsed {
    V1(super::Header),
    V2(Header),
}

fn read_any_header<R: Read>(r: &mut R) -> io::Result<Parsed> {
    let not_elk = || {
        io_error(Error::InvalidEncoding {
            scheme: "elk (not an easylock file)",
        })
    };
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(|_| not_elk())?;
    if &magic == super::MAGIC {
        let mut h = [0u8; super::HEADER_LEN];
        h[..4].copy_from_slice(&magic);
        r.read_exact(&mut h[4..]).map_err(|_| not_elk())?;
        return super::parse_header(&h).map(Parsed::V1).map_err(io_error);
    }
    if &magic == elk2::MAGIC {
        return Header::read_after_magic(&mut |b: &mut [u8]| {
            r.read_exact(b).map_err(|_| Error::InvalidEncoding {
                scheme: "elk2 header (truncated)",
            })
        })
        .map(Parsed::V2)
        .map_err(io_error);
    }
    Err(not_elk())
}

fn info_of(p: &Parsed) -> Info {
    match p {
        Parsed::V1(h) => Info {
            version: 1,
            cipher: h.cipher,
            archive: false,
            password_slots: vec![h.params],
            recipients: 0,
        },
        Parsed::V2(h) => Info {
            version: 2,
            cipher: h.cipher,
            archive: h.is_archive(),
            password_slots: h.password_slots(),
            recipients: h.recipient_slots(),
        },
    }
}

/// Read only the header of an encrypted file.
pub fn inspect<R: Read>(mut r: R) -> io::Result<Info> {
    read_any_header(&mut r).map(|p| info_of(&p))
}

/// Read the header of an `ELK1` or `ELK2` file, unlock it with any of `creds`, and
/// return a [`Decryptor`] over the plaintext plus the file's [`Info`].
pub fn decrypt<R: Read>(mut r: R, creds: &[Credential<'_>]) -> io::Result<(Decryptor<R>, Info)> {
    let parsed = read_any_header(&mut r)?;
    let info = info_of(&parsed);
    let dec = match parsed {
        Parsed::V1(h) => {
            // ELK1 has no key check, so only the first password is tried.
            let pw = creds
                .iter()
                .find_map(|c| match c {
                    Credential::Password(p) => Some(*p),
                    Credential::Identity(_) => None,
                })
                .ok_or_else(|| io_error(Error::Authentication))?;
            let mut key = argon2::hash(pw, &h.salt, h.params).map_err(io_error)?;
            let k: [u8; 32] = key[..32].try_into().expect("32-byte key");
            key.zeroize();
            Decryptor::new(r, h.cipher, &k, h.base_nonce)
        }
        Parsed::V2(h) => {
            let fk = h.unlock(creds).map_err(io_error)?;
            let mut k = fk.payload_key(&h.base_nonce);
            let d = Decryptor::new(r, h.cipher, &k, h.base_nonce);
            k.zeroize();
            d
        }
    }
    .map_err(io_error)?;
    Ok((dec, info))
}

/// Encrypt an in-memory buffer (convenience for small inputs and WebAssembly).
pub fn seal_bytes(
    data: &[u8],
    opts: &EncryptOptions<'_>,
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<Vec<u8>> {
    let mut run = || -> io::Result<Vec<u8>> {
        let mut enc = encrypt(Vec::with_capacity(data.len() + 4096), opts, rng)?;
        enc.write_all(data)?;
        enc.finish()
    };
    run().map_err(|e| core_error(&e).cloned().unwrap_or(Error::Authentication))
}

/// Decrypt an in-memory `.elk` file (`ELK1` or `ELK2`).
pub fn open_bytes(data: &[u8], creds: &[Credential<'_>]) -> Result<(Vec<u8>, Info)> {
    let run = || -> io::Result<(Vec<u8>, Info)> {
        let (mut dec, info) = decrypt(data, creds)?;
        let mut out = Vec::with_capacity(data.len());
        dec.read_to_end(&mut out)?;
        Ok((out, info))
    };
    run().map_err(|e| core_error(&e).cloned().unwrap_or(Error::Authentication))
}

#[cfg(test)]
mod tests {
    use super::super::elk2::{Identity, SlotSpec};
    use super::*;
    use crate::kdf::argon2::Params;

    fn rng() -> impl FnMut(&mut [u8]) {
        let mut s = 0xdead_beef_cafe_f00du64;
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

    fn pw_opts(c: Cipher) -> EncryptOptions<'static> {
        EncryptOptions {
            cipher: c,
            slots: vec![SlotSpec::Password {
                password: b"pw",
                params: FAST,
            }],
            flags: 0,
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_many_sizes_and_write_patterns() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 70 * CHUNK + 5] {
            let d = data(len);
            for c in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
                // write in awkward 100_003-byte pieces to exercise buffering
                let mut enc = encrypt(Vec::new(), &pw_opts(c), &mut rng()).unwrap();
                for piece in d.chunks(100_003) {
                    enc.write_all(piece).unwrap();
                }
                let file = enc.finish().unwrap();
                let (out, info) = open_bytes(&file, &[Credential::Password(b"pw")]).unwrap();
                assert_eq!(out, d, "len {len}");
                assert_eq!(info.version, 2);
            }
        }
    }

    #[test]
    fn matches_legacy_in_memory_reader_layout() {
        // Every chunk must have the exact ELK1 layout, so `open_file`-style parsing works.
        let d = data(CHUNK * 2);
        let file = seal_bytes(&d, &pw_opts(Cipher::ChaCha20Poly1305), &mut rng()).unwrap();
        let (h, hl) = elk2::Header::parse(&file).unwrap();
        assert_eq!(h.password_slots().len(), 1);
        // 2 full chunks + 1 empty final chunk
        assert_eq!(file.len() - hl, 3 * 4 + 2 * (CHUNK + 16) + 16);
    }

    #[test]
    fn reads_elk1_files() {
        let d = data(CHUNK + 99);
        let v1 = super::super::seal_file(&d, b"old", Cipher::Aes256Gcm, FAST, &mut rng()).unwrap();
        let (out, info) = open_bytes(&v1, &[Credential::Password(b"old")]).unwrap();
        assert_eq!(out, d);
        assert_eq!(info.version, 1);
        assert!(open_bytes(&v1, &[Credential::Password(b"new")]).is_err());
    }

    #[test]
    fn truncation_trailing_data_and_bitflips_fail() {
        let d = data(5 * CHUNK + 10);
        let file = seal_bytes(&d, &pw_opts(Cipher::Aes256Gcm), &mut rng()).unwrap();
        let ok = |f: &[u8]| open_bytes(f, &[Credential::Password(b"pw")]).is_ok();
        assert!(ok(&file));
        assert!(!ok(&file[..file.len() - 1]));
        let (_, hl) = elk2::Header::parse(&file).unwrap();
        assert!(!ok(&file[..hl + 4 + CHUNK + 16])); // cut at a chunk boundary
        let mut extra = file.clone();
        extra.push(0);
        assert!(!ok(&extra));
        let mut flip = file.clone();
        flip[hl + 4 + 3 * (CHUNK + 20)] ^= 0x80;
        assert!(!ok(&flip));
    }

    #[test]
    fn recipients_and_archive_flag() {
        let mut r = rng();
        let id = Identity::generate(&mut r);
        let rec = id.recipient();
        let opts = EncryptOptions {
            cipher: Cipher::ChaCha20Poly1305,
            slots: vec![SlotSpec::Recipient(&rec)],
            flags: elk2::FLAG_ARCHIVE,
        };
        let file = seal_bytes(b"to alice", &opts, &mut r).unwrap();
        let info = inspect(&file[..]).unwrap();
        assert!(info.archive && info.recipients == 1 && info.password_slots.is_empty());
        let (out, _) = open_bytes(&file, &[Credential::Identity(&id)]).unwrap();
        assert_eq!(out, b"to alice");
        assert!(open_bytes(&file, &[Credential::Password(b"pw")]).is_err());
    }
}
