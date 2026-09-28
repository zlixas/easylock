// The dashboard's crypto backend. Everything runs in-browser via the
// easylock-core WebAssembly module — no server, no network.
import { wasm } from "./wasm.js";

// --- byte / string helpers ------------------------------------------

export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function randomHex(bytes) {
  return bytesToHex(wasm.random_bytes(bytes));
}
export function hexToBytes(hex) {
  const h = hex.trim().replace(/\s+/g, "").replace(/^0x/i, "");
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("invalid hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export function bytesToHex(b) {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
export function bytesToB64(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64ToBytes(b64) {
  const clean = b64.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const bin = atob(clean + "===".slice((clean.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function bytesToB64url(b) {
  return bytesToB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Let the browser paint (status text, spinners) before a slow wasm call. */
export const yieldUI = () => new Promise((r) => setTimeout(r, 30));

// --- worker bridge ------------------------------------------------------

let worker = null;
let seq = 0;
const pending = new Map();

/** Run `fn` in the crypto worker; resolves with its result. */
function inWorker(fn, ...args) {
  if (!worker) {
    worker = new Worker(new URL("./crypto.worker.js", import.meta.url), { type: "module" });
    worker.onmessage = ({ data }) => {
      const p = pending.get(data.id);
      pending.delete(data.id);
      if (!p) return;
      if (data.ok) p.resolve(data.result);
      else p.reject(new Error(data.error));
    };
    worker.onerror = (e) => {
      for (const p of pending.values()) p.reject(new Error(e.message || "crypto worker failed"));
      pending.clear();
      worker = null;
    };
  }
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, fn, args });
  });
}

// --- API --------------------------------------------------------------

export const api = {
  version: () => wasm.version(),
  buildInfo: () => wasm.build_info(),

  hash: (algo, bytes) => wasm.hash(algo, bytes),
  hashAll: (bytes) => wasm.hash_all(bytes),
  hmac: (algo, key, data) => wasm.hmac(algo, key, data),
  hkdf: (ikm, salt, info, len) => bytesToHex(wasm.hkdf_sha256(ikm, salt, info, len)),

  aeadSeal: (alg, key, nonce, aad, pt) => wasm.aead_seal(alg, key, nonce, aad, pt),
  aeadOpen: (alg, key, nonce, aad, ct) => wasm.aead_open(alg, key, nonce, aad, ct),

  // Slow / memory-hard operations run in the worker and return promises.
  argon2Phc: (password, salt, m, t, p) => inWorker("argon2Phc", password, salt, m, t, p),
  argon2Verify: (password, phc) => inWorker("argon2Verify", password, phc),
  pbkdf2: async (password, salt, iterations, outLen) =>
    bytesToHex(await inWorker("pbkdf2", password, salt, iterations, outLen)),

  encode: (input, steps, decode) => wasm.encode_pipeline(input, steps, decode),

  password(opts) {
    const p = wasm.gen_password(opts.length, opts.lower, opts.upper, opts.digits, opts.symbols);
    const pool = (opts.lower ? 24 : 0) + (opts.upper ? 23 : 0) + (opts.digits ? 8 : 0) + (opts.symbols ? 12 : 0);
    return { password: p, bits: Math.round(p.length * Math.log2(pool || 2) * 10) / 10 };
  },

  keygen: (kind) => wasm.keygen(kind),
  keygenAsync: (kind) => inWorker("keygen", kind),
  mlkemEncaps: (param, ekHex) => wasm.mlkem_encaps(param, ekHex),
  mlkemDecaps: (param, dkHex, ctHex) => wasm.mlkem_decaps(param, dkHex, ctHex),

  x25519: (scalarHex, pointHex) => wasm.x25519(scalarHex, pointHex),
  x25519Public: (secretHex) => wasm.x25519_public(secretHex),
  edSign: (seedHex, msg) => wasm.ed25519_sign(seedHex, msg),
  edVerify: (publicHex, msg, sigHex) => wasm.ed25519_verify(publicHex, msg, sigHex),

  elkSeal: (data, pw, recipients, cipher) => inWorker("elkSeal", data, pw, recipients, cipher),
  elkOpen: (data, pw, identity) => inWorker("elkOpen", data, pw, identity),
  elkInfo: (data) => wasm.elk_info(data),
  identityGenerate: () => wasm.identity_generate(),
  identityPublic: (secret) => wasm.identity_public(secret.trim()),
  elkSealToken: (text, pw, cipher) => inWorker("elkSealToken", text, pw, cipher),
  elkOpenToken: (token, pw) => inWorker("elkOpenToken", token, pw),

  random: (n) => wasm.random_bytes(n),
  /** Start the worker early (also caches it for offline use). */
  warmWorker: () => inWorker("ping").catch(() => {}),
};
