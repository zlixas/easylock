//! Criterion micro-benchmarks for the hot primitives.
//!
//! Run with `cargo bench -p easylock-core`. Throughput is reported per byte
//! for the bulk primitives.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use easylock_core::aead::{Aead, Aes256Gcm, ChaCha20Poly1305};
use easylock_core::cipher::aes::Aes256;
use easylock_core::ec::{x25519_base, SigningKey};
use easylock_core::hash::Hash;
use easylock_core::hash::{Keccak256, Sha256, Sha512};

const SIZES: [usize; 3] = [64, 1024, 65536];

fn bench_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");
    for size in SIZES {
        let data = vec![0x61u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, d| {
            b.iter(|| {
                let mut h = Sha256::init();
                h.update(black_box(d));
                black_box(h.finalize_vec())
            });
        });
        group.bench_with_input(BenchmarkId::new("sha512", size), &data, |b, d| {
            b.iter(|| {
                let mut h = Sha512::init();
                h.update(black_box(d));
                black_box(h.finalize_vec())
            });
        });
        group.bench_with_input(BenchmarkId::new("keccak256", size), &data, |b, d| {
            b.iter(|| {
                let mut h = Keccak256::init();
                h.update(black_box(d));
                black_box(h.finalize_vec())
            });
        });
    }
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead-seal");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let gcm = Aes256Gcm::new(&key).unwrap();
    let chacha = ChaCha20Poly1305::new(&key).unwrap();
    for size in SIZES {
        let pt = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("aes-256-gcm", size), &pt, |b, p| {
            b.iter(|| black_box(gcm.seal(&nonce, b"", black_box(p))));
        });
        group.bench_with_input(BenchmarkId::new("chacha20-poly1305", size), &pt, |b, p| {
            b.iter(|| black_box(chacha.seal(&nonce, b"", black_box(p))));
        });
    }
    group.finish();
}

fn bench_aes_block(c: &mut Criterion) {
    let aes = Aes256::new(&[0u8; 32]).unwrap();
    c.bench_function("aes256-encrypt-block", |b| {
        let mut blk = [0u8; 16];
        b.iter(|| {
            aes.encrypt_block_into(black_box(&mut blk));
            black_box(blk)
        });
    });
}

fn bench_curve25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("curve25519");
    let seed = [7u8; 32];
    group.bench_function("x25519-base", |b| {
        b.iter(|| black_box(x25519_base(black_box(&seed))));
    });
    let sk = SigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    let msg = b"benchmark message payload";
    let sig = sk.sign(msg);
    group.bench_function("ed25519-sign", |b| {
        b.iter(|| black_box(sk.sign(black_box(msg))));
    });
    group.bench_function("ed25519-verify", |b| {
        b.iter(|| black_box(vk.verify(black_box(msg), &sig)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hashes,
    bench_aead,
    bench_aes_block,
    bench_curve25519
);
criterion_main!(benches);
