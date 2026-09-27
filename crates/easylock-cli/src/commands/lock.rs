//! `easylock lock` / `unlock` / `inspect`: streaming, multi-core `.elk` encryption of
//! files **and folders**, to a password and/or public keys (`-r elkpub1…`).
//!
//! Outputs are written to a temporary file next to the destination and renamed only
//! after everything succeeded, so an interrupted or failed run never leaves a
//! half-written file behind or clobbers existing data.

use crate::commands::identity;
use crate::i18n::{CliError, Lang, Msg};
use crate::io::{prompt_secret, rng};
use crate::progress::{human_bytes, Counting, Progress};
use easylock_core::container::elk2::{Credential, Identity, Recipient, SlotSpec, FLAG_ARCHIVE};
use easylock_core::container::stream::{self, core_error, EncryptOptions, Info};
use easylock_core::container::{archive, Cipher, FILE_PARAMS};
use easylock_core::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const IO_BUF: usize = 1 << 20;

#[derive(clap::Args, Debug, Clone)]
pub struct LockArgs {
    /// Files or folders to encrypt (`-` = stdin).
    #[arg(value_name = "PATH", required = true)]
    pub inputs: Vec<PathBuf>,

    /// Output file (default: PATH.elk; `-` = stdout). Single input only.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// aes-256-gcm or chacha20-poly1305.
    #[arg(short, long, default_value = "chacha20-poly1305")]
    pub cipher: String,

    /// Encrypt to a public key (`elkpub1…`) or a file of keys; repeatable.
    #[arg(short = 'r', long = "recipient", value_name = "KEY|FILE")]
    pub recipients: Vec<String>,

    /// Password (prefer the prompt or `EASYLOCK_PASSWORD`; flags leak into shell history).
    #[arg(short, long)]
    pub password: Option<String>,

    /// With -r: also allow unlocking with a password.
    #[arg(long)]
    pub with_password: bool,

    /// After encrypting, overwrite and delete the original.
    #[arg(long)]
    pub shred: bool,

    /// Replace an existing output file.
    #[arg(short, long)]
    pub force: bool,

    /// No progress or status output.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct UnlockArgs {
    /// `.elk` files to decrypt (`-` = stdin).
    #[arg(value_name = "FILE", required = true)]
    pub inputs: Vec<PathBuf>,

    /// Output file or folder (default: FILE without `.elk`; `-` = stdout). Single input only.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Password (prefer the prompt or `EASYLOCK_PASSWORD`).
    #[arg(short, long)]
    pub password: Option<String>,

    /// Identity file(s) for files encrypted to a public key; repeatable.
    #[arg(short, long, value_name = "FILE")]
    pub identity: Vec<PathBuf>,

    /// List the contents instead of extracting.
    #[arg(short, long)]
    pub list: bool,

    /// Replace an existing output file.
    #[arg(short, long)]
    pub force: bool,

    /// No progress or status output.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct InspectArgs {
    /// `.elk` files to describe (no password needed).
    #[arg(value_name = "FILE", required = true)]
    pub inputs: Vec<PathBuf>,
}

// ------------------------------------------------------------------ helpers

fn is_stdio(p: &Path) -> bool {
    p.as_os_str() == "-"
}

fn read_err(path: &Path, e: &io::Error) -> CliError {
    CliError::new(Msg::ReadError(format!("{}: {e}", path.display())))
}

fn write_err(path: &Path, e: &io::Error) -> CliError {
    CliError::new(Msg::WriteError(format!("{}: {e}", path.display())))
}

/// Map a streaming error: authentication failures get the friendly message.
fn stream_err(path: &Path, e: &io::Error) -> CliError {
    match core_error(e) {
        Some(Error::Authentication) => CliError::new(Msg::AuthenticationFailed),
        Some(other) => CliError::new(Msg::Crypto(format!("{}: {other}", path.display()))),
        None => read_err(path, e),
    }
}

pub(crate) fn password_from_env(flag: Option<&String>) -> Option<String> {
    flag.cloned()
        .or_else(|| std::env::var("EASYLOCK_PASSWORD").ok())
}

pub(crate) fn ask_password(lang: Lang, confirm: bool) -> Result<String, CliError> {
    let first = prompt_secret(lang.pick(["Password", "Parola", "Contraseña"]))?;
    if confirm {
        let again = prompt_secret(lang.pick([
            "Repeat password",
            "Parolayı tekrarlayın",
            "Repita la contraseña",
        ]))?;
        if first != again {
            return Err(CliError::new(Msg::PasswordsDiffer));
        }
    }
    if first.is_empty() {
        return Err(CliError::new(Msg::PasswordEmpty));
    }
    Ok(first)
}

/// Parse `-r` values: `elkpub1…` keys, or files containing them (e.g. an identity file).
pub(crate) fn load_recipients(specs: &[String]) -> Result<Vec<Recipient>, CliError> {
    let mut out = Vec::new();
    for spec in specs {
        let bad = || CliError::new(Msg::BadRecipient(spec.clone()));
        if spec.trim().starts_with("elkpub1") {
            out.push(Recipient::parse(spec).map_err(|_| bad())?);
            continue;
        }
        let text = fs::read_to_string(spec).map_err(|_| bad())?;
        let before = out.len();
        for tok in text.split_whitespace().filter(|t| t.starts_with("elkpub1")) {
            out.push(Recipient::parse(tok).map_err(|_| bad())?);
        }
        if out.len() == before {
            return Err(bad());
        }
    }
    Ok(out)
}

/// A temporary output that is removed on drop unless committed.
struct TempOut {
    tmp: PathBuf,
    dest: PathBuf,
    committed: bool,
}

impl TempOut {
    fn new(dest: &Path, force: bool) -> Result<Self, CliError> {
        if dest.exists() && !(force && dest.is_file()) {
            return Err(CliError::new(Msg::OutputExists(dest.display().to_string())));
        }
        let mut name = dest.as_os_str().to_owned();
        name.push(format!(".part-{}", std::process::id()));
        Ok(TempOut {
            tmp: PathBuf::from(name),
            dest: dest.to_path_buf(),
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), CliError> {
        fs::rename(&self.tmp, &self.dest).map_err(|e| write_err(&self.dest, &e))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.tmp);
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match fs::symlink_metadata(e.path()) {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) if m.is_file() => m.len(),
            _ => 0,
        })
        .sum()
}

/// Overwrite a file (or every file in a folder) with zeros, then delete it.
pub(crate) fn shred_path(p: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(p)?;
    if meta.is_dir() {
        for e in fs::read_dir(p)? {
            shred_path(&e?.path())?;
        }
        return fs::remove_dir(p);
    }
    if meta.is_file() {
        let mut f = fs::OpenOptions::new().write(true).open(p)?;
        let zeros = vec![0u8; IO_BUF];
        let mut left = meta.len();
        while left > 0 {
            let n = usize::try_from(left.min(IO_BUF as u64)).unwrap_or(IO_BUF);
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(p)
}

/// `io::copy` with a 1 MiB buffer (far fewer syscalls on large files).
fn copy_big(r: &mut impl Read, w: &mut impl Write) -> io::Result<u64> {
    let mut buf = vec![0u8; IO_BUF];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
}

fn status(quiet: bool, line: &str) {
    if !quiet {
        eprintln!("easylock {line}");
    }
}

// --------------------------------------------------------------------- lock

pub fn run_lock(args: &LockArgs, lang: Lang) -> Result<(), CliError> {
    let cipher = Cipher::parse(&args.cipher)
        .ok_or_else(|| CliError::new(Msg::UnknownCipher(args.cipher.clone())))?;
    if args.output.is_some() && args.inputs.len() > 1 {
        return Err(CliError::new(Msg::OneOutputOnly));
    }
    let recipients = load_recipients(&args.recipients)?;
    let wants_password = recipients.is_empty() || args.with_password || args.password.is_some();
    let mut password = if wants_password {
        match password_from_env(args.password.as_ref()) {
            Some(p) => Some(p),
            None if args.inputs.iter().any(|p| is_stdio(p)) && recipients.is_empty() => {
                return Err(CliError::new(Msg::StdinNeedsKey));
            }
            None => Some(ask_password(lang, true)?),
        }
    } else {
        None
    };
    if password.as_deref() == Some("") {
        return Err(CliError::new(Msg::PasswordEmpty));
    }

    let mut slots: Vec<SlotSpec<'_>> = recipients.iter().map(SlotSpec::Recipient).collect();
    if let Some(pw) = &password {
        slots.push(SlotSpec::Password {
            password: pw.as_bytes(),
            params: FILE_PARAMS,
        });
    }

    if args.inputs.len() == 1 {
        let r = lock_one(&args.inputs[0], args, cipher, &slots, lang);
        drop(slots);
        if let Some(p) = password.as_mut() {
            crate::io::wipe(p);
        }
        return r;
    }
    let mut failed = 0usize;
    for input in &args.inputs {
        if let Err(e) = lock_one(input, args, cipher, &slots, lang) {
            eprintln!("easylock: {}: {}", input.display(), e.msg.text(lang));
            failed += 1;
        }
    }
    drop(slots);
    if let Some(p) = password.as_mut() {
        crate::io::wipe(p);
    }
    if failed > 0 {
        return Err(CliError::new(Msg::SomeFailed(failed)));
    }
    Ok(())
}

fn default_elk_name(input: &Path) -> PathBuf {
    // `folder/` → `folder.elk`, `a.txt` → `a.txt.elk`
    let mut name = input.components().collect::<PathBuf>().into_os_string();
    name.push(".elk");
    PathBuf::from(name)
}

#[allow(clippy::too_many_lines)] // one linear flow: plan → encrypt → commit → shred
fn lock_one(
    input: &Path,
    args: &LockArgs,
    cipher: Cipher,
    slots: &[SlotSpec<'_>],
    lang: Lang,
) -> Result<(), CliError> {
    let stdin_in = is_stdio(input);
    let is_dir = !stdin_in && input.is_dir();
    let out_path = match &args.output {
        Some(o) => o.clone(),
        None if stdin_in => PathBuf::from("-"),
        None => default_elk_name(input),
    };
    let opts = EncryptOptions {
        cipher,
        slots: slots.to_vec(),
        flags: if is_dir { FLAG_ARCHIVE } else { 0 },
    };

    let total = if stdin_in {
        None
    } else if is_dir {
        Some(dir_size(input))
    } else {
        Some(fs::metadata(input).map_err(|e| read_err(input, &e))?.len())
    };
    let mut progress = Progress::new(
        lang.pick(["encrypting", "şifreleniyor", "cifrando"]),
        total,
        args.quiet,
    );
    let mut skipped = 0;

    let mut write_to = |w: &mut dyn Write, progress: &mut Progress| -> Result<(), CliError> {
        let mut enc = stream::encrypt(w, &opts, &mut rng()).map_err(|e| stream_err(input, &e))?;
        if is_dir {
            let st = archive::pack(input, &mut enc, &mut |b| progress.set(b))
                .map_err(|e| read_err(input, &e))?;
            skipped = st.skipped;
            progress.finish();
            if st.skipped > 0 {
                eprintln!("easylock: {}", Msg::SkippedSpecial(st.skipped).text(lang));
            }
            status(
                args.quiet,
                &Msg::ArchiveSummary {
                    files: st.files,
                    dirs: st.dirs,
                    size: human_bytes(st.bytes),
                }
                .text(lang),
            );
        } else if stdin_in {
            copy_big(&mut io::stdin().lock(), &mut enc).map_err(|e| read_err(input, &e))?;
        } else {
            let f = File::open(input).map_err(|e| read_err(input, &e))?;
            copy_big(
                &mut Counting {
                    inner: f,
                    progress: &mut *progress,
                },
                &mut enc,
            )
            .map_err(|e| read_err(input, &e))?;
        }
        enc.finish().map_err(|e| write_err(input, &e))?;
        Ok(())
    };

    if is_stdio(&out_path) {
        let mut out = BufWriter::with_capacity(IO_BUF, io::stdout().lock());
        write_to(&mut out, &mut progress)?;
        out.flush().map_err(|e| write_err(&out_path, &e))?;
        progress.finish();
    } else {
        let tmp = TempOut::new(&out_path, args.force)?;
        let mut f = File::create(&tmp.tmp).map_err(|e| write_err(&out_path, &e))?;
        write_to(&mut f, &mut progress)?;
        f.sync_all().map_err(|e| write_err(&out_path, &e))?;
        drop(f);
        tmp.commit()?;
        progress.finish();
        status(
            args.quiet,
            &Msg::Encrypted {
                target: out_path.display().to_string(),
                cipher: cipher.name().into(),
            }
            .text(lang),
        );
    }
    let recipients = slots
        .iter()
        .filter(|s| matches!(s, SlotSpec::Recipient(_)))
        .count();
    let password = slots.iter().any(|s| matches!(s, SlotSpec::Password { .. }));
    status(
        args.quiet,
        &Msg::SlotsSummary {
            recipients,
            password,
        }
        .text(lang),
    );

    if args.shred && !stdin_in {
        if skipped > 0 {
            eprintln!(
                "easylock: {}",
                Msg::ShredSkipped(input.display().to_string()).text(lang)
            );
        } else {
            shred_path(input).map_err(|e| write_err(input, &e))?;
            status(
                args.quiet,
                &Msg::Shredded(input.display().to_string()).text(lang),
            );
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- unlock

fn open_input(p: &Path) -> Result<Box<dyn Read>, CliError> {
    if is_stdio(p) {
        return Ok(Box::new(BufReader::with_capacity(IO_BUF, io::stdin())));
    }
    let f = File::open(p).map_err(|e| read_err(p, &e))?;
    Ok(Box::new(BufReader::with_capacity(IO_BUF, f)))
}

pub fn run_unlock(args: &UnlockArgs, lang: Lang) -> Result<(), CliError> {
    if args.output.is_some() && args.inputs.len() > 1 {
        return Err(CliError::new(Msg::OneOutputOnly));
    }
    let mut ids: Vec<Identity> = args
        .identity
        .iter()
        .map(|p| identity::load(p, lang))
        .collect::<Result<_, _>>()?;
    let mut password = password_from_env(args.password.as_ref());

    // A single input reports its own error directly (e.g. "authentication failed").
    if args.inputs.len() == 1 {
        let r = unlock_one(&args.inputs[0], args, &mut ids, &mut password, lang);
        if let Some(p) = password.as_mut() {
            crate::io::wipe(p);
        }
        return r;
    }
    let mut failed = 0usize;
    for input in &args.inputs {
        if let Err(e) = unlock_one(input, args, &mut ids, &mut password, lang) {
            eprintln!("easylock: {}: {}", input.display(), e.msg.text(lang));
            failed += 1;
        }
    }
    if let Some(p) = password.as_mut() {
        crate::io::wipe(p);
    }
    if failed > 0 {
        return Err(CliError::new(Msg::SomeFailed(failed)));
    }
    Ok(())
}

fn unlock_one(
    input: &Path,
    args: &UnlockArgs,
    ids: &mut Vec<Identity>,
    password: &mut Option<String>,
    lang: Lang,
) -> Result<(), CliError> {
    // stdin can only be read once, so its header can't be inspected separately.
    let info = if is_stdio(input) {
        None
    } else {
        Some(stream::inspect(open_input(input)?).map_err(|e| stream_err(input, &e))?)
    };
    let (needs_pw, needs_id) = info.as_ref().map_or((true, false), |i| {
        (!i.password_slots.is_empty(), i.recipients > 0)
    });

    if needs_id && ids.is_empty() {
        let def = identity::default_path();
        if def.exists() {
            ids.push(identity::load(&def, lang)?);
        } else if !needs_pw {
            return Err(CliError::new(Msg::NeedIdentity));
        }
    }
    if needs_pw && password.is_none() && (ids.is_empty() || !needs_id) {
        *password = Some(ask_password(lang, false)?);
    }

    let attempt = |pw: Option<&String>, ids: &[Identity]| {
        let mut creds: Vec<Credential<'_>> = ids.iter().map(Credential::Identity).collect();
        if let Some(p) = pw {
            creds.push(Credential::Password(p.as_bytes()));
        }
        stream::decrypt(open_input(input)?, &creds).map_err(|e| stream_err(input, &e))
    };
    let (dec, info) = match attempt(password.as_ref(), ids) {
        Ok(v) => v,
        // The identity didn't fit, but a password slot exists: ask for it.
        Err(e) if matches!(e.msg, Msg::AuthenticationFailed) && needs_pw && password.is_none() => {
            *password = Some(ask_password(lang, false)?);
            attempt(password.as_ref(), &[])?
        }
        Err(e) => return Err(e),
    };
    write_plaintext(input, dec, &info, args, lang)
}

fn write_plaintext(
    input: &Path,
    dec: impl Read,
    info: &Info,
    args: &UnlockArgs,
    lang: Lang,
) -> Result<(), CliError> {
    let total = if is_stdio(input) {
        None
    } else {
        fs::metadata(input).ok().map(|m| m.len())
    };
    let mut progress = Progress::new(
        lang.pick(["decrypting", "çözülüyor", "descifrando"]),
        total,
        args.quiet || args.list,
    );
    let mut dec = BufReader::with_capacity(IO_BUF, dec);

    if args.list {
        if info.archive {
            let entries = archive::list(&mut dec).map_err(|e| stream_err(input, &e))?;
            for e in entries {
                let size = if e.is_dir {
                    "-".to_string()
                } else {
                    human_bytes(e.size)
                };
                println!(
                    "{:>10}  {}{}",
                    size,
                    e.path,
                    if e.is_dir { "/" } else { "" }
                );
            }
        } else {
            let n = io::copy(&mut dec, &mut io::sink()).map_err(|e| stream_err(input, &e))?;
            println!(
                "{:>10}  {}",
                human_bytes(n),
                default_plain_name(input).display()
            );
        }
        return Ok(());
    }

    let out_path = args.output.clone().unwrap_or_else(|| {
        if is_stdio(input) {
            PathBuf::from("-")
        } else {
            default_plain_name(input)
        }
    });

    if is_stdio(&out_path) {
        if info.archive {
            return Err(CliError::new(Msg::FolderToStdout));
        }
        let mut out = io::stdout().lock();
        copy_big(&mut dec, &mut out).map_err(|e| stream_err(input, &e))?;
        out.flush().map_err(|e| write_err(&out_path, &e))?;
        return Ok(());
    }

    let tmp = TempOut::new(&out_path, args.force && !info.archive)?;
    if info.archive {
        fs::create_dir(&tmp.tmp).map_err(|e| write_err(&out_path, &e))?;
        let st = archive::unpack(&mut dec, &tmp.tmp, &mut |b| progress.set(b))
            .map_err(|e| stream_err(input, &e))?;
        tmp.commit()?;
        progress.finish();
        status(
            args.quiet,
            &Msg::ArchiveSummary {
                files: st.files,
                dirs: st.dirs,
                size: human_bytes(st.bytes),
            }
            .text(lang),
        );
    } else {
        let mut f = File::create(&tmp.tmp).map_err(|e| write_err(&out_path, &e))?;
        copy_big(
            &mut Counting {
                inner: dec,
                progress: &mut progress,
            },
            &mut f,
        )
        .map_err(|e| stream_err(input, &e))?;
        f.sync_all().map_err(|e| write_err(&out_path, &e))?;
        drop(f);
        tmp.commit()?;
        progress.finish();
    }
    status(
        args.quiet,
        &Msg::Decrypted {
            target: out_path.display().to_string(),
            cipher: info.cipher.name().into(),
        }
        .text(lang),
    );
    Ok(())
}

fn default_plain_name(input: &Path) -> PathBuf {
    let s = input.to_string_lossy();
    match s.strip_suffix(".elk") {
        Some(base) if !base.is_empty() && !base.ends_with('/') => PathBuf::from(base),
        _ => PathBuf::from(format!("{s}.dec")),
    }
}

// ------------------------------------------------------------------ inspect

pub fn run_inspect(args: &InspectArgs, lang: Lang) -> Result<(), CliError> {
    for input in &args.inputs {
        let info = stream::inspect(open_input(input)?).map_err(|e| stream_err(input, &e))?;
        let size = fs::metadata(input)
            .map(|m| human_bytes(m.len()))
            .unwrap_or_default();
        let row = |k: [&str; 3], v: String| println!("  {:<12}{v}", lang.pick(k));
        println!("{}", input.display());
        row(
            ["format", "biçim", "formato"],
            format!("ELK{}", info.version),
        );
        row(
            ["cipher", "şifre", "cifrado"],
            info.cipher.name().to_string(),
        );
        row(
            ["contents", "içerik", "contenido"],
            lang.pick(if info.archive {
                ["folder archive", "klasör arşivi", "archivo de carpeta"]
            } else {
                ["single file", "tek dosya", "archivo único"]
            })
            .to_string(),
        );
        for p in &info.password_slots {
            row(
                ["password", "parola", "contraseña"],
                format!(
                    "Argon2id m={} MiB t={} p={}",
                    p.m_cost / 1024,
                    p.t_cost,
                    p.parallelism
                ),
            );
        }
        if info.recipients > 0 {
            row(
                ["recipients", "alıcılar", "destinatarios"],
                format!("{} × X25519 + ML-KEM-768", info.recipients),
            );
        }
        row(["size", "boyut", "tamaño"], size);
    }
    Ok(())
}
