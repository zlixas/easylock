//! `easylock keygen <kind>` — Ed25519, X25519, ML-KEM (Kyber) and RSA key pairs.

use crate::i18n::{CliError, Lang, Msg};
use crate::io::os_random;
use easylock_core::ec::{SigningKey, StaticSecret};
use easylock_core::encode::hex;
use easylock_core::pqc::{mlkem, MlKem1024, MlKem512, MlKem768};

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Key type: ed25519, x25519, mlkem512, mlkem768, mlkem1024, rsa2048.
    #[arg(value_name = "KIND", default_value = "ed25519")]
    pub kind: String,

    /// Output as JSON instead of labelled lines.
    #[arg(long)]
    pub json: bool,
}

/// A generated key pair, hex / text encoded.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub kind: &'static str,
    pub public: String,
    pub secret: String,
}

fn rng_fill(buf: &mut [u8]) {
    os_random(buf).expect("OS randomness unavailable");
}

/// Generate a key pair of the given kind.
pub fn generate(kind: &str) -> Result<KeyPair, CliError> {
    let k = kind.trim().to_ascii_lowercase().replace(['-', '_'], "");
    Ok(match k.as_str() {
        "ed25519" => {
            let mut seed = [0u8; 32];
            os_random(&mut seed)?;
            let sk = SigningKey::from_seed(seed);
            KeyPair {
                kind: "Ed25519",
                public: hex::encode(sk.verifying_key().as_bytes()),
                secret: hex::encode(&sk.to_seed()),
            }
        }
        "x25519" => {
            let mut s = [0u8; 32];
            os_random(&mut s)?;
            let sk = StaticSecret::from_bytes(s);
            KeyPair {
                kind: "X25519",
                public: hex::encode(sk.public_key().as_bytes()),
                secret: hex::encode(&sk.to_bytes()),
            }
        }
        "mlkem512" | "mlkem768" | "mlkem1024" | "kyber512" | "kyber768" | "kyber1024" => {
            let params = if k.ends_with("512") {
                &MlKem512
            } else if k.ends_with("1024") {
                &MlKem1024
            } else {
                &MlKem768
            };
            let (ek, dk) = mlkem::keygen(params, &mut rng_fill);
            KeyPair {
                kind: params.name,
                public: hex::encode(&ek),
                secret: hex::encode(&dk),
            }
        }
        "rsa2048" | "rsa" => {
            let sk = easylock_core::rsa::keygen::generate_rsa2048(&mut rng_fill)
                .map_err(CliError::crypto)?;
            let c = sk.export_components();
            KeyPair {
                kind: "RSA-2048",
                public: format!("n={} e={}", hex::encode(&c.n), c.e),
                secret: format!(
                    "p={} q={} dp={} dq={} qinv={}",
                    hex::encode(&c.p),
                    hex::encode(&c.q),
                    hex::encode(&c.dp),
                    hex::encode(&c.dq),
                    hex::encode(&c.qinv)
                ),
            }
        }
        _ => return Err(CliError::new(Msg::UnknownKeyKind(kind.to_string()))),
    })
}

pub fn run(args: &Args, lang: Lang) -> Result<(), CliError> {
    let kp = generate(&args.kind)?;
    if args.json {
        println!(
            "{{\"kind\":\"{}\",\"public\":\"{}\",\"secret\":\"{}\"}}",
            kp.kind, kp.public, kp.secret
        );
    } else {
        println!("# {}", kp.kind);
        println!(
            "{}: {}",
            lang.pick(["public", "açık", "pública"]),
            kp.public
        );
        println!(
            "{}: {}",
            lang.pick(["secret", "gizli", "secreta"]),
            kp.secret
        );
        eprintln!(
            "easylock: {}",
            lang.pick([
                "keep the secret key private — it is printed only once",
                "gizli anahtarı kimseyle paylaşmayın — yalnızca bir kez yazdırılır",
                "mantenga la clave secreta en privado — solo se muestra una vez",
            ])
        );
    }
    Ok(())
}
