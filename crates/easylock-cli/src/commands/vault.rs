//! `easylock vault …`: an encrypted folder where files *stay* encrypted. Names,
//! sizes and contents are hidden; files are added, listed, read and removed
//! without plaintext ever touching the vault directory.

use crate::commands::identity;
use crate::commands::lock::{ask_password, load_recipients, password_from_env};
use crate::i18n::{CliError, Lang, Msg};
use crate::io::rng;
use crate::progress::{human_bytes, Counting, Progress};
use clap::Subcommand;
use easylock_core::container::elk2::{Credential, Identity, Recipient, SlotSpec};
use easylock_core::container::stream::core_error;
use easylock_core::container::vault::{Entry, Vault};
use easylock_core::container::{Cipher, FILE_PARAMS};
use easylock_core::Error;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Option<Sub>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Sub {
    /// Create a new vault.
    Init(KeyArgs),
    /// Encrypt files or folders into the vault.
    Add(AddArgs),
    /// List what the vault contains.
    Ls(LsArgs),
    /// Decrypt files out of the vault.
    Get(GetArgs),
    /// Print a file from the vault to stdout.
    Cat(CatArgs),
    /// Remove files or folders from the vault.
    Rm(RmArgs),
    /// Change the password / public keys that open the vault.
    Passwd(KeyArgs),
    /// Show how the vault can be unlocked (no password needed).
    Info(InfoArgs),
}

/// How to open an existing vault.
#[derive(clap::Args, Debug, Clone)]
pub struct Open {
    /// Vault directory.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Password (prefer the prompt or `EASYLOCK_PASSWORD`).
    #[arg(short, long)]
    pub password: Option<String>,
    /// Identity file(s) for vaults locked to a public key.
    #[arg(short, long, value_name = "FILE")]
    pub identity: Vec<PathBuf>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct KeyArgs {
    #[command(flatten)]
    pub open: Open,
    /// aes-256-gcm or chacha20-poly1305 (init only).
    #[arg(short, long, default_value = "chacha20-poly1305")]
    pub cipher: String,
    /// Public key(s) that may open the vault (`elkpub1…` or a file); repeatable.
    #[arg(short = 'r', long = "recipient", value_name = "KEY|FILE")]
    pub recipients: Vec<String>,
    /// With -r: also allow a password.
    #[arg(long)]
    pub with_password: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct AddArgs {
    #[command(flatten)]
    pub open: Open,
    /// Files or folders to add.
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,
    /// Store under this folder inside the vault.
    #[arg(long = "as", value_name = "FOLDER")]
    pub prefix: Option<String>,
    /// After adding, overwrite and delete the originals.
    #[arg(long)]
    pub shred: bool,
    /// No progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct LsArgs {
    #[command(flatten)]
    pub open: Open,
    /// Only show this file or folder.
    #[arg(value_name = "PREFIX")]
    pub prefix: Option<String>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct GetArgs {
    #[command(flatten)]
    pub open: Open,
    /// Files or folders inside the vault.
    #[arg(value_name = "NAME", required = true)]
    pub names: Vec<String>,
    /// Destination folder (default: current folder).
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Replace existing files.
    #[arg(short, long)]
    pub force: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct CatArgs {
    #[command(flatten)]
    pub open: Open,
    /// File inside the vault.
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(clap::Args, Debug, Clone)]
pub struct RmArgs {
    #[command(flatten)]
    pub open: Open,
    /// Files or folders inside the vault.
    #[arg(value_name = "NAME", required = true)]
    pub names: Vec<String>,
}

#[derive(clap::Args, Debug, Clone)]
pub struct InfoArgs {
    /// Vault directory.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
}

fn verr(e: &io::Error) -> CliError {
    match core_error(e) {
        Some(Error::Authentication) => CliError::new(Msg::AuthenticationFailed),
        _ => CliError::new(Msg::Vault(e.to_string())),
    }
}

/// Unlock a vault: identities first (explicit or default), then a password.
fn open_vault(o: &Open, lang: Lang) -> Result<Vault, CliError> {
    let info = Vault::info(&o.vault).map_err(|e| verr(&e))?;
    let mut ids: Vec<Identity> = o
        .identity
        .iter()
        .map(|p| identity::load(p, lang))
        .collect::<Result<_, _>>()?;
    if info.recipients > 0 && ids.is_empty() {
        let def = identity::default_path();
        if def.exists() {
            ids.push(identity::load(&def, lang)?);
        } else if info.password_slots.is_empty() {
            return Err(CliError::new(Msg::NeedIdentity));
        }
    }
    let mut pw = password_from_env(o.password.as_ref());
    let try_open = |pw: Option<&String>| {
        let mut creds: Vec<Credential<'_>> = ids.iter().map(Credential::Identity).collect();
        if let Some(p) = pw {
            creds.push(Credential::Password(p.as_bytes()));
        }
        Vault::open(&o.vault, &creds).map_err(|e| verr(&e))
    };
    if pw.is_none() && ids.is_empty() {
        pw = Some(ask_password(lang, false)?);
    }
    let r = match try_open(pw.as_ref()) {
        Err(e)
            if matches!(e.msg, Msg::AuthenticationFailed)
                && pw.is_none()
                && !info.password_slots.is_empty() =>
        {
            pw = Some(ask_password(lang, false)?);
            try_open(pw.as_ref())
        }
        other => other,
    };
    if let Some(p) = pw.as_mut() {
        crate::io::wipe(p);
    }
    r
}

/// Password + recipients for `init` / `passwd`.
fn run_with_slots(
    k: &KeyArgs,
    lang: Lang,
    f: impl FnOnce(&[SlotSpec<'_>]) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let recipients: Vec<Recipient> = load_recipients(&k.recipients)?;
    let mut pw = if recipients.is_empty() || k.with_password || k.open.password.is_some() {
        Some(match password_from_env(k.open.password.as_ref()) {
            Some(p) => p,
            None => ask_password(lang, true)?,
        })
    } else {
        None
    };
    if pw.as_deref() == Some("") {
        return Err(CliError::new(Msg::PasswordEmpty));
    }
    let mut slots: Vec<SlotSpec<'_>> = recipients.iter().map(SlotSpec::Recipient).collect();
    if let Some(p) = &pw {
        slots.push(SlotSpec::Password {
            password: p.as_bytes(),
            params: FILE_PARAMS,
        });
    }
    let r = f(&slots);
    drop(slots);
    if let Some(p) = pw.as_mut() {
        crate::io::wipe(p);
    }
    r
}

fn mtime_mode(meta: &fs::Metadata) -> (i64, u32) {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    (mtime, mode)
}

/// Collect `(vault path, file path)` pairs for `path`, recursing into folders.
fn collect(
    path: &Path,
    name: &str,
    out: &mut Vec<(String, PathBuf)>,
    skipped: &mut u64,
) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_file() {
        out.push((name.to_string(), path.to_path_buf()));
    } else if meta.is_dir() {
        let mut kids: Vec<_> = fs::read_dir(path)?.collect::<io::Result<_>>()?;
        kids.sort_by_key(fs::DirEntry::file_name);
        for k in kids {
            let child = k.file_name().to_string_lossy().into_owned();
            collect(&k.path(), &format!("{name}/{child}"), out, skipped)?;
        }
    } else {
        *skipped += 1;
    }
    Ok(())
}

fn print_entries(entries: &[&Entry]) {
    for e in entries {
        let date = format_date(e.mtime);
        println!("{:>10}  {date}  {}", human_bytes(e.size), e.path);
    }
    let total: u64 = entries.iter().map(|e| e.size).sum();
    eprintln!("{} · {}", entries.len(), human_bytes(total));
}

/// `YYYY-MM-DD` from unix seconds (UTC, civil-from-days).
fn format_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let Some(cmd) = &args.cmd else {
        return Ok(()); // `main` prints the localized help when no subcommand is given
    };
    match cmd {
        Sub::Init(k) => {
            let cipher = Cipher::parse(&k.cipher)
                .ok_or_else(|| CliError::new(Msg::UnknownCipher(k.cipher.clone())))?;
            run_with_slots(k, lang, |slots| {
                Vault::create(&k.open.vault, cipher, slots, &mut rng()).map_err(|e| verr(&e))?;
                eprintln!(
                    "easylock {}",
                    Msg::VaultCreated(k.open.vault.display().to_string()).text(lang)
                );
                Ok(())
            })
        }
        Sub::Passwd(k) => {
            let mut v = open_vault(&k.open, lang)?;
            run_with_slots(k, lang, |slots| {
                v.rekey(slots, &mut rng()).map_err(|e| verr(&e))
            })?;
            eprintln!("easylock {}", Msg::VaultRekeyed.text(lang));
            Ok(())
        }
        Sub::Info(i) => {
            let info = Vault::info(&i.vault).map_err(|e| verr(&e))?;
            println!("{}", i.vault.display());
            for p in &info.password_slots {
                println!(
                    "  {:<12}Argon2id m={} MiB t={} p={}",
                    lang.pick(["password", "parola", "contraseña"]),
                    p.m_cost / 1024,
                    p.t_cost,
                    p.parallelism
                );
            }
            if info.recipients > 0 {
                println!(
                    "  {:<12}{} × X25519 + ML-KEM-768",
                    lang.pick(["recipients", "alıcılar", "destinatarios"]),
                    info.recipients
                );
            }
            Ok(())
        }
        Sub::Add(a) => run_add(a, lang),
        Sub::Ls(l) => {
            let v = open_vault(&l.open, lang)?;
            print_entries(&v.find(l.prefix.as_deref().unwrap_or("")));
            Ok(())
        }
        Sub::Cat(c) => {
            let v = open_vault(&c.open, lang)?;
            if !v
                .entries()
                .iter()
                .any(|e| e.path == c.name.trim_matches('/'))
            {
                return Err(CliError::new(Msg::VaultMissing(c.name.clone())));
            }
            let mut r = v.read(&c.name).map_err(|e| verr(&e))?;
            let mut out = io::stdout().lock();
            io::copy(&mut r, &mut out).map_err(|e| verr(&e))?;
            out.flush().map_err(|e| verr(&e))
        }
        Sub::Get(g) => run_get(g, lang),
        Sub::Rm(r) => {
            let mut v = open_vault(&r.open, lang)?;
            let mut n = 0;
            for name in &r.names {
                let k = v.remove(name).map_err(|e| verr(&e))?;
                if k == 0 {
                    return Err(CliError::new(Msg::VaultMissing(name.clone())));
                }
                n += k;
            }
            v.save(&mut rng()).map_err(|e| verr(&e))?;
            eprintln!("easylock {}", Msg::VaultRemoved(n).text(lang));
            Ok(())
        }
    }
}

fn run_add(a: &AddArgs, lang: Lang) -> Result<(), CliError> {
    let mut v = open_vault(&a.open, lang)?;
    v.lock().map_err(|e| verr(&e))?;
    let mut items = Vec::new();
    let mut skipped = 0;
    for p in &a.paths {
        let base = p.file_name().map_or_else(
            || p.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let name = match &a.prefix {
            Some(pre) => format!("{}/{base}", pre.trim_matches('/')),
            None => base,
        };
        collect(p, &name, &mut items, &mut skipped)
            .map_err(|e| CliError::new(Msg::ReadError(format!("{}: {e}", p.display()))))?;
    }
    if skipped > 0 {
        eprintln!("easylock: {}", Msg::SkippedSpecial(skipped).text(lang));
    }
    let total: u64 = items
        .iter()
        .filter_map(|(_, p)| fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let mut progress = Progress::new(
        lang.pick(["encrypting", "şifreleniyor", "cifrando"]),
        Some(total),
        a.quiet,
    );
    let mut r = rng();
    let mut bytes = 0;
    for (name, path) in &items {
        let meta = fs::metadata(path)
            .map_err(|e| CliError::new(Msg::ReadError(format!("{}: {e}", path.display()))))?;
        let (mtime, mode) = mtime_mode(&meta);
        let f = File::open(path)
            .map_err(|e| CliError::new(Msg::ReadError(format!("{}: {e}", path.display()))))?;
        bytes += v
            .add(
                name,
                &mut Counting {
                    inner: f,
                    progress: &mut progress,
                },
                mtime,
                mode,
                &mut r,
            )
            .map_err(|e| verr(&e))?;
    }
    // Commit the index before touching any originals.
    v.save(&mut r).map_err(|e| verr(&e))?;
    progress.finish();
    eprintln!(
        "easylock {}",
        Msg::VaultAdded {
            files: items.len() as u64,
            size: human_bytes(bytes)
        }
        .text(lang)
    );
    if a.shred {
        if skipped > 0 {
            for p in &a.paths {
                eprintln!(
                    "easylock: {}",
                    Msg::ShredSkipped(p.display().to_string()).text(lang)
                );
            }
        } else {
            for p in &a.paths {
                super::lock::shred_path(p)
                    .map_err(|e| CliError::new(Msg::WriteError(format!("{}: {e}", p.display()))))?;
                eprintln!(
                    "easylock {}",
                    Msg::Shredded(p.display().to_string()).text(lang)
                );
            }
        }
    }
    Ok(())
}

fn run_get(g: &GetArgs, lang: Lang) -> Result<(), CliError> {
    let v = open_vault(&g.open, lang)?;
    let out_dir = g.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let mut wanted: Vec<Entry> = Vec::new();
    for name in &g.names {
        let found = v.find(name);
        if found.is_empty() {
            return Err(CliError::new(Msg::VaultMissing(name.clone())));
        }
        wanted.extend(found.into_iter().cloned());
    }
    let mut n = 0u64;
    let mut bytes = 0u64;
    for e in &wanted {
        // Vault paths were validated when added and when the index was read.
        let target = out_dir.join(e.path.split('/').collect::<PathBuf>());
        if target.exists() && !g.force {
            return Err(CliError::new(Msg::OutputExists(
                target.display().to_string(),
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|er| {
                CliError::new(Msg::WriteError(format!("{}: {er}", parent.display())))
            })?;
        }
        let tmp = target.with_extension(format!("part-{}", std::process::id()));
        let res = (|| -> io::Result<u64> {
            let mut r = v.read(&e.path)?;
            let mut f = File::create(&tmp)?;
            let k = io::copy(&mut r, &mut f)?;
            f.set_modified(
                std::time::UNIX_EPOCH
                    + std::time::Duration::from_secs(u64::try_from(e.mtime).unwrap_or(0)),
            )?;
            f.sync_all()?;
            Ok(k)
        })();
        match res {
            Ok(k) => {
                fs::rename(&tmp, &target).map_err(|er| {
                    CliError::new(Msg::WriteError(format!("{}: {er}", target.display())))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(e.mode));
                }
                bytes += k;
                n += 1;
            }
            Err(er) => {
                let _ = fs::remove_file(&tmp);
                return Err(verr(&er));
            }
        }
    }
    eprintln!(
        "easylock {} {}",
        lang.pick(["decrypted", "çözüldü", "descifrado"]),
        Msg::ArchiveSummary {
            files: n,
            dirs: 0,
            size: human_bytes(bytes)
        }
        .text(lang)
    );
    Ok(())
}
