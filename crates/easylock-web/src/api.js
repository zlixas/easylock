// Thin fetch wrapper over easylock-server. Same-origin in production; Vite
// proxies `/v1` + `/health` to :8080 in dev.

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

export const api = {
  health: () => fetch("/health").then((r) => r.json()),

  hash: (algo, data, isHex = false) =>
    post("/v1/hash", { algo, data, hex: isHex }).then((r) => r.digest_hex),

  aeadSeal: (alg, keyHex, nonceHex, aadHex, plaintextB64) =>
    post("/v1/aead/seal", {
      alg, key_hex: keyHex, nonce_hex: nonceHex, aad_hex: aadHex, plaintext: plaintextB64,
    }).then((r) => r.ciphertext),

  aeadOpen: (alg, keyHex, nonceHex, aadHex, ciphertextB64) =>
    post("/v1/aead/open", {
      alg, key_hex: keyHex, nonce_hex: nonceHex, aad_hex: aadHex, ciphertext: ciphertextB64,
    }).then((r) => r.plaintext),

  argon2: (password, opts) =>
    post("/v1/kdf/argon2", { password, ...opts }),

  pbkdf2: (password, saltHex, iterations, outLen, hash) =>
    post("/v1/kdf/pbkdf2", { password, salt_hex: saltHex, iterations, out_len: outLen, hash })
      .then((r) => r.digest_hex),

  encode: (input, steps, decode) =>
    post("/v1/encode", { input, steps, decode }).then((r) => r.output),

  password: (opts) => post("/v1/password", opts),

  keygen: (kind) => post("/v1/keygen", { kind }),

  mlkemEncaps: (param, ekHex) => post("/v1/mlkem/encaps", { param, ek_hex: ekHex }),
  mlkemDecaps: (param, dkHex, ctHex) =>
    post("/v1/mlkem/decaps", { param, dk_hex: dkHex, ciphertext_hex: ctHex }).then((r) => r.digest_hex),

  x25519: (scalarHex, pointHex) =>
    post("/v1/x25519", { scalar_hex: scalarHex, point_hex: pointHex }).then((r) => r.shared_hex),

  edSign: (seedHex, messageB64) =>
    post("/v1/ed25519/sign", { seed_hex: seedHex, message: messageB64 }),
  edVerify: (publicHex, messageB64, sigHex) =>
    post("/v1/ed25519/verify", { public_hex: publicHex, message: messageB64, sig_hex: sigHex })
      .then((r) => r.valid),
};

// --- browser-side helpers ---------------------------------------------

export function randomHex(bytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function toB64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}
export function fromB64(b64) {
  return decodeURIComponent(escape(atob(b64)));
}
