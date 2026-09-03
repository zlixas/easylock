// Loads the easylock-core WebAssembly module. `wasm-pack build --target web`
// generates `src/pkg/` (see `npm run wasm`).
import init, * as wasm from "./pkg/easylock_wasm.js";

let ready = null;

/** Initialise the WASM module once; safe to await repeatedly. */
export function initWasm() {
  if (!ready) ready = init().then(() => wasm);
  return ready;
}

export { wasm };
