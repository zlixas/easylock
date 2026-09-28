// Runs the slow, memory-hard operations (Argon2id, file encryption, RSA key
// generation) off the main thread so the page stays responsive.
import init, * as wasm from "./pkg/easylock_wasm.js";

const ready = init();
const enc = new TextEncoder();

const fns = {
  ping: () => true,
  elkSeal: (data, pw, recipients, cipher) => wasm.elk_seal(data, enc.encode(pw), recipients, cipher, false),
  elkOpen: (data, pw, identity) => wasm.elk_open(data, enc.encode(pw), identity),
  elkSealToken: (text, pw, cipher) => wasm.elk_seal_token(text, enc.encode(pw), cipher),
  elkOpenToken: (token, pw) => wasm.elk_open_token(token.trim(), enc.encode(pw)),
  argon2Phc: (pw, salt, m, t, p) => wasm.argon2id_phc(enc.encode(pw), salt, m, t, p),
  argon2Verify: (pw, phc) => wasm.argon2_verify(enc.encode(pw), phc.trim()),
  pbkdf2: (pw, salt, iterations, outLen) => wasm.pbkdf2_sha256(enc.encode(pw), salt, iterations, outLen),
  keygen: (kind) => wasm.keygen(kind),
};

self.onmessage = async ({ data: { id, fn, args } }) => {
  try {
    await ready;
    const result = fns[fn](...args);
    // Hand large byte results over without copying.
    self.postMessage({ id, ok: true, result }, result instanceof Uint8Array ? [result.buffer] : []);
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};
