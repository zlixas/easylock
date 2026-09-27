//! A minimal, streaming folder archive (`ELKA`) used as the payload of encrypted
//! folders (`std` only).
//!
//! ```text
//! "ELKA" ‖ version u8 (=1)
//! entry* ‖ 0x00                     (0x00 = end of archive)
//! entry  = kind u8 (1 = dir, 2 = file) ‖ path_len u16 ‖ path (UTF-8, '/'-separated)
//!          ‖ mode u32 ‖ mtime i64 (unix seconds) ‖ [size u64 ‖ data]   (files only)
//! ```
//!
//! Extraction is hardened against hostile archives: paths must be relative and made
//! only of normal components (no `..`, `.`, empty parts, drive letters, backslashes or
//! NUL), files are created with `create_new` (never overwriting or following an
//! existing path), symlinks are neither stored nor created, and permission bits are
//! limited to `0o777`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Archive magic.
pub const MAGIC: &[u8; 4] = b"ELKA";
const VERSION: u8 = 1;
const END: u8 = 0;
const DIR: u8 = 1;
const FILE: u8 = 2;
const MAX_PATH: usize = 4096;

/// Counters returned by [`pack`] and [`unpack`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Regular files.
    pub files: u64,
    /// Directories (excluding the root).
    pub dirs: u64,
    /// Total file bytes.
    pub bytes: u64,
    /// Entries skipped while packing (symlinks, sockets, devices…).
    pub skipped: u64,
}

/// One archive entry, as returned by [`list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Relative `/`-separated path.
    pub path: String,
    /// `true` for directories.
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Unix permission bits (`0o777` mask).
    pub mode: u32,
    /// Modification time (unix seconds).
    pub mtime: i64,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}
#[cfg(not(unix))]
fn mode_of(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else if meta.is_dir() {
        0o755
    } else {
        0o644
    }
}

fn mtime_of(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn write_head(w: &mut impl Write, kind: u8, path: &str, mode: u32, mtime: i64) -> io::Result<()> {
    let len = u16::try_from(path.len()).map_err(|_| invalid("path too long for archive"))?;
    w.write_all(&[kind])?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(path.as_bytes())?;
    w.write_all(&mode.to_le_bytes())?;
    w.write_all(&mtime.to_le_bytes())
}

/// Recursively archive the *contents* of directory `root` into `w`.
/// `progress` is called with the number of file bytes written so far.
pub fn pack<W: Write>(root: &Path, w: &mut W, progress: &mut dyn FnMut(u64)) -> io::Result<Stats> {
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION])?;
    let mut stats = Stats::default();
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let mut entries: Vec<fs::DirEntry> = fs::read_dir(&dir)?.collect::<io::Result<_>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        let mut subdirs = Vec::new();
        for e in entries {
            let name = e.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("file name is not valid UTF-8"))?;
            let path = if rel.is_empty() {
                name.to_owned()
            } else {
                format!("{rel}/{name}")
            };
            let meta = fs::symlink_metadata(e.path())?;
            if meta.is_dir() {
                write_head(w, DIR, &path, mode_of(&meta), mtime_of(&meta))?;
                stats.dirs += 1;
                subdirs.push((e.path(), path));
            } else if meta.is_file() {
                write_head(w, FILE, &path, mode_of(&meta), mtime_of(&meta))?;
                let size = meta.len();
                w.write_all(&size.to_le_bytes())?;
                let copied = io::copy(&mut File::open(e.path())?.take(size), w)?;
                if copied != size {
                    return Err(io::Error::other(format!(
                        "{path} changed size while being archived"
                    )));
                }
                stats.files += 1;
                stats.bytes += size;
                progress(stats.bytes);
            } else {
                stats.skipped += 1; // symlinks and special files are not archived
            }
        }
        // Reverse so directories are visited in sorted order (stack is LIFO).
        stack.extend(subdirs.into_iter().rev());
    }
    w.write_all(&[END])?;
    Ok(stats)
}

fn read_u<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)?;
    Ok(b)
}

/// Validate an archive path and turn it into a safe relative `PathBuf`.
pub(crate) fn safe_relative(path: &str) -> io::Result<PathBuf> {
    let bad = || invalid("unsafe path in archive");
    if path.is_empty() || path.len() > MAX_PATH || path.contains(['\\', '\0', ':']) {
        return Err(bad());
    }
    let mut out = PathBuf::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(bad());
        }
        let p = Path::new(part);
        if !matches!(p.components().next(), Some(Component::Normal(_)))
            || p.components().count() != 1
        {
            return Err(bad());
        }
        out.push(part);
    }
    Ok(out)
}

struct Head {
    kind: u8,
    path: String,
    mode: u32,
    mtime: i64,
    size: u64,
}

fn read_head(r: &mut impl Read) -> io::Result<Option<Head>> {
    let [kind] = read_u::<1>(r)?;
    if kind == END {
        return Ok(None);
    }
    if kind != DIR && kind != FILE {
        return Err(invalid("unknown archive entry kind"));
    }
    let len = usize::from(u16::from_le_bytes(read_u::<2>(r)?));
    let mut p = vec![0u8; len];
    r.read_exact(&mut p)?;
    let path = String::from_utf8(p).map_err(|_| invalid("archive path is not UTF-8"))?;
    let mode = u32::from_le_bytes(read_u::<4>(r)?) & 0o777;
    let mtime = i64::from_le_bytes(read_u::<8>(r)?);
    let size = if kind == FILE {
        u64::from_le_bytes(read_u::<8>(r)?)
    } else {
        0
    };
    Ok(Some(Head {
        kind,
        path,
        mode,
        mtime,
        size,
    }))
}

fn check_magic(r: &mut impl Read) -> io::Result<()> {
    let m = read_u::<5>(r)?;
    if &m[..4] != MAGIC || m[4] != VERSION {
        return Err(invalid("not an easylock folder archive"));
    }
    Ok(())
}

/// List the entries of an archive without extracting anything.
pub fn list<R: Read>(r: &mut R) -> io::Result<Vec<Entry>> {
    check_magic(r)?;
    let mut out = Vec::new();
    while let Some(h) = read_head(r)? {
        safe_relative(&h.path)?;
        if h.kind == FILE && io::copy(&mut r.take(h.size), &mut io::sink())? != h.size {
            return Err(invalid("archive truncated"));
        }
        out.push(Entry {
            path: h.path,
            is_dir: h.kind == DIR,
            size: h.size,
            mode: h.mode,
            mtime: h.mtime,
        });
    }
    Ok(out)
}

#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn to_time(secs: i64) -> SystemTime {
    u64::try_from(secs).map_or(UNIX_EPOCH, |s| UNIX_EPOCH + Duration::from_secs(s))
}

/// Extract an archive into the existing, empty directory `dest`.
pub fn unpack<R: Read>(r: &mut R, dest: &Path, progress: &mut dyn FnMut(u64)) -> io::Result<Stats> {
    check_magic(r)?;
    let mut stats = Stats::default();
    let mut dir_meta: Vec<(PathBuf, u32, i64)> = Vec::new();
    while let Some(h) = read_head(r)? {
        let target = dest.join(safe_relative(&h.path)?);
        if h.kind == DIR {
            fs::create_dir_all(&target)?;
            dir_meta.push((target, h.mode, h.mtime));
            stats.dirs += 1;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            if io::copy(&mut r.take(h.size), &mut f)? != h.size {
                return Err(invalid("archive truncated"));
            }
            f.set_modified(to_time(h.mtime))?;
        }
        set_mode(&target, h.mode)?;
        stats.files += 1;
        stats.bytes += h.size;
        progress(stats.bytes);
    }
    // Apply directory metadata last (deepest first) so we could write into them.
    for (dir, mode, mtime) in dir_meta.into_iter().rev() {
        if let Ok(f) = File::open(&dir) {
            let _ = f.set_modified(to_time(mtime));
        }
        set_mode(&dir, mode | 0o700)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("easylock-archive-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn pack_list_unpack_roundtrip() {
        let src = tmp("src");
        fs::create_dir_all(src.join("a/b")).unwrap();
        fs::create_dir_all(src.join("empty")).unwrap();
        fs::write(src.join("top.txt"), b"hello").unwrap();
        fs::write(src.join("a/b/deep.bin"), vec![7u8; 300_000]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();

        let mut buf = Vec::new();
        let st = pack(&src, &mut buf, &mut |_| {}).unwrap();
        assert_eq!((st.files, st.dirs, st.bytes), (2, 3, 300_005));
        #[cfg(unix)]
        assert_eq!(st.skipped, 1);

        let names: Vec<String> = list(&mut &buf[..])
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            names.contains(&"a/b/deep.bin".to_string()) && names.contains(&"empty".to_string())
        );

        let dst = tmp("dst");
        unpack(&mut &buf[..], &dst, &mut |_| {}).unwrap();
        assert_eq!(fs::read(dst.join("top.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(dst.join("a/b/deep.bin")).unwrap().len(), 300_000);
        assert!(dst.join("empty").is_dir());
        assert!(!dst.join("link").exists());
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(&dst);
    }

    #[test]
    fn hostile_paths_are_rejected() {
        for p in [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "a//b",
            "./x",
            "C:evil",
            "a\\..\\b",
            "",
        ] {
            assert!(safe_relative(p).is_err(), "{p:?} should be rejected");
            let mut a = Vec::new();
            a.extend_from_slice(MAGIC);
            a.push(VERSION);
            write_head(&mut a, FILE, p, 0o644, 0).ok();
            a.extend_from_slice(&1u64.to_le_bytes());
            a.push(b'x');
            a.push(END);
            let dst = tmp("hostile");
            assert!(unpack(&mut &a[..], &dst, &mut |_| {}).is_err());
            let _ = fs::remove_dir_all(&dst);
        }
        assert!(safe_relative("ok/fine.txt").is_ok());
    }

    #[test]
    fn duplicate_entries_do_not_overwrite() {
        let mut a = Vec::new();
        a.extend_from_slice(MAGIC);
        a.push(VERSION);
        for body in [b"first", b"secnd"] {
            write_head(&mut a, FILE, "same.txt", 0o644, 0).unwrap();
            a.extend_from_slice(&5u64.to_le_bytes());
            a.extend_from_slice(body);
        }
        a.push(END);
        let dst = tmp("dup");
        assert!(unpack(&mut &a[..], &dst, &mut |_| {}).is_err());
        assert_eq!(fs::read(dst.join("same.txt")).unwrap(), b"first");
        let _ = fs::remove_dir_all(&dst);
    }
}
