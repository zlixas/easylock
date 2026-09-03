// The dashboard's crypto backend. Everything runs in-browser via the
// easylock-core WebAssembly module — no server, no network.
import { wasm } from "./wasm.js";

// --- byte / string helpers ------------------------------------------

export function randomHex(bytes) {
  return bytesToHex(wasm.random_bytes(bytes));
}
export function hexToBytes(hex) {
  const h = hex.trim().replace(/\s+/g, "");
  if (h.length % 2) throw new Error("odd-length hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export function bytesToHex(b) {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
export function toB64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}
export function fromB64(b64) {
  return decodeURIComponent(escape(atob(b64)));
}
function b64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(b) {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
const enc = new TextEncoder();

// --- API (same shape the tool views expect) ------------------------

export const api = {
  async health() {
    return {
      version: wasm.version(),
      aes_backend: "wasm (portable-ct)",
      ghash_backend: "wasm (portable-ct)",
      build: wasm.build_info(),
    };
  },

  hash(algo, dataB64, isHex = false) {
    const bytes = isHex ? hexToBytes(dataB64) : b64ToBytes(dataB64);
    return wasm.hash(algo, bytes);
  },

  aeadSeal(alg, keyHex, nonceHex, aadHex, plaintextB64) {
    const ct = wasm.aead_seal(
      alg, hexToBytes(keyHex), hexToBytes(nonceHex),
      aadHex ? hexToBytes(aadHex) : new Uint8Array(), b64ToBytes(plaintextB64),
    );
    return bytesToB64(ct);
  },
  aeadOpen(alg, keyHex, nonceHex, aadHex, ciphertextB64) {
    const pt = wasm.aead_open(
      alg, hexToBytes(keyHex), hexToBytes(nonceHex),
      aadHex ? hexToBytes(aadHex) : new Uint8Array(), b64ToBytes(ciphertextB64),
    );
    return bytesToB64(pt);
  },

  argon2(password, opts) {
    const salt = opts.salt_hex ? hexToBytes(opts.salt_hex) : wasm.random_bytes(16);
    const m = opts.m_cost ?? 65536, tt = opts.t_cost ?? 3, p = opts.parallelism ?? 4;
    const tag = wasm.argon2id(enc.encode(password), salt, m, tt, p, 32);
    const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return {
      tag_hex: bytesToHex(tag),
      salt_hex: bytesToHex(salt),
      phc: `$argon2id$v=19$m=${m},t=${tt},p=${p}$${b64u(salt)}$${b64u(tag)}`,
    };
  },
  pbkdf2(password, saltHex, iterations, outLen) {
    return bytesToHex(wasm.pbkdf2_sha256(enc.encode(password), hexToBytes(saltHex), iterations, outLen));
  },

  encode(input, steps, decode) {
    return wasm.encode_pipeline(input, steps, decode);
  },

  password(opts) {
    const p = wasm.gen_password(
      opts.length ?? 20,
      opts.lower ?? true, opts.upper ?? true, opts.digits ?? true, opts.symbols ?? false,
    );
    const pool =
      (opts.lower ?? true ? 24 : 0) + (opts.upper ?? true ? 23 : 0) +
      (opts.digits ?? true ? 8 : 0) + (opts.symbols ? 12 : 0);
    return { password: p, bits_of_entropy: Math.round(p.length * Math.log2(pool || 2) * 10) / 10 };
  },

  keygen(kind) {
    return wasm.keygen(kind);
  },
  mlkemEncaps(param, ekHex) {
    return wasm.mlkem_encaps(param, ekHex);
  },
  mlkemDecaps(param, dkHex, ctHex) {
    return wasm.mlkem_decaps(param, dkHex, ctHex);
  },

  x25519(scalarHex, pointHex) {
    return wasm.x25519(scalarHex, pointHex);
  },
  edSign(seedHex, messageB64) {
    return wasm.ed25519_sign(seedHex, b64ToBytes(messageB64));
  },
  edVerify(publicHex, messageB64, sigHex) {
    return wasm.ed25519_verify(publicHex, b64ToBytes(messageB64), sigHex);
  },
};
