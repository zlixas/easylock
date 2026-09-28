//! End-to-end tests of the real `easylock` binary for file encryption, public
//! keys, vaults and help (run on Linux, macOS and Windows in CI).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_easylock"));
    c.env("EASYLOCK_PASSWORD", "correct horse battery staple")
        .env("EASYLOCK_IDENTITY", "/nonexistent/identity.key")
        .env_remove("EASYLOCK_IDENTITY_PASSWORD")
        .env("LANG", "en_US.UTF-8");
    c
}

fn run(args: &[&str], cwd: &Path) -> Output {
    bin()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .expect("run easylock")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("easylock-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn every_command_prints_help_in_every_language() {
    let d = tmp("help");
    for lang in ["en", "tr", "es"] {
        for cmd in [
            &["lock"][..],
            &["unlock"],
            &["inspect"],
            &["identity"],
            &["vault", "add"],
            &["sign"],
            &["verify"],
            &["hash"],
            &["kdf"],
            &["keygen"],
            &["password"],
            &[],
        ] {
            let mut args = vec!["--lang", lang];
            args.extend_from_slice(cmd);
            args.push("--help");
            let out = run(&args, &d);
            assert!(
                out.status.success(),
                "{lang} {cmd:?} --help failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!out.stdout.is_empty());
        }
    }
}

#[test]
fn lock_unlock_file_and_folder_roundtrip() {
    let d = tmp("roundtrip");
    std::fs::write(d.join("a.txt"), b"hello from the CLI test").unwrap();
    std::fs::create_dir_all(d.join("dir").join("sub")).unwrap();
    std::fs::write(d.join("dir").join("sub").join("b.bin"), vec![7u8; 300_000]).unwrap();

    assert!(run(&["lock", "a.txt", "dir", "-q"], &d).status.success());
    std::fs::remove_file(d.join("a.txt")).unwrap();
    std::fs::remove_dir_all(d.join("dir")).unwrap();

    let info = run(&["inspect", "dir.elk"], &d);
    assert!(String::from_utf8_lossy(&info.stdout).contains("folder"));

    assert!(run(&["unlock", "a.txt.elk", "dir.elk", "-q"], &d)
        .status
        .success());
    assert_eq!(
        std::fs::read(d.join("a.txt")).unwrap(),
        b"hello from the CLI test"
    );
    assert_eq!(
        std::fs::read(d.join("dir").join("sub").join("b.bin"))
            .unwrap()
            .len(),
        300_000
    );

    // a wrong password fails and leaves nothing behind
    let bad = bin()
        .args(["unlock", "a.txt.elk", "-o", "x.txt"])
        .env("EASYLOCK_PASSWORD", "nope")
        .current_dir(&d)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(!d.join("x.txt").exists());
    // an existing output is never overwritten without --force
    assert!(!run(&["unlock", "a.txt.elk"], &d).status.success());
}

#[test]
fn public_key_encryption_roundtrip() {
    let d = tmp("pubkey");
    let id = run(&["identity", "-o", "me.key", "--plain"], &d);
    assert!(
        id.status.success(),
        "{}",
        String::from_utf8_lossy(&id.stderr)
    );
    let public = String::from_utf8(id.stdout).unwrap();
    assert!(public.starts_with("elkpub1"));
    std::fs::write(d.join("msg.txt"), b"for my eyes only").unwrap();
    assert!(run(
        &[
            "lock",
            "msg.txt",
            "-r",
            public.trim(),
            "-o",
            "msg.elk",
            "-q"
        ],
        &d
    )
    .status
    .success());
    assert!(run(
        &["unlock", "msg.elk", "-i", "me.key", "-o", "out.txt", "-q"],
        &d
    )
    .status
    .success());
    assert_eq!(
        std::fs::read(d.join("out.txt")).unwrap(),
        b"for my eyes only"
    );
}

#[test]
fn vault_add_list_get_remove() {
    let d = tmp("vault");
    std::fs::write(d.join("secret.txt"), b"vault contents").unwrap();
    assert!(run(&["vault", "init", "v"], &d).status.success());
    assert!(run(&["vault", "add", "v", "secret.txt", "-q"], &d)
        .status
        .success());
    assert!(String::from_utf8_lossy(&run(&["vault", "ls", "v"], &d).stdout).contains("secret.txt"));
    assert_eq!(
        run(&["vault", "cat", "v", "secret.txt"], &d).stdout,
        b"vault contents"
    );
    assert!(run(&["vault", "get", "v", "secret.txt", "-o", "out"], &d)
        .status
        .success());
    assert_eq!(
        std::fs::read(d.join("out").join("secret.txt")).unwrap(),
        b"vault contents"
    );
    assert!(run(&["vault", "rm", "v", "secret.txt"], &d)
        .status
        .success());
    assert!(
        !String::from_utf8_lossy(&run(&["vault", "ls", "v"], &d).stdout).contains("secret.txt")
    );
}
