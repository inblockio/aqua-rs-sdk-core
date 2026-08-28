import { ensureReady } from "./wasm.js";

/** Version of the underlying `aqua-rs-sdk-core-wasm` crate (lockstep with the core). */
export function version(): string {
  return ensureReady().version();
}
