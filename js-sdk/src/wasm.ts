/**
 * Module loading and the JSON boundary helpers.
 *
 * The wasm package is built by wasm-pack with `--target web`, whose default
 * export is an async `init` accepting a URL, `Response`, `BufferSource`, or
 * compiled `WebAssembly.Module`. Browsers can pass nothing and let the
 * package fetch its own `.wasm` next to its JS; Node has no `fetch` for
 * `file:` URLs, so `init()` reads the bytes from disk there.
 */

import initWasm, * as wasm from "aqua-rs-sdk-core-wasm";
import type { InitInput, SyncInitInput } from "aqua-rs-sdk-core-wasm";
import type { Method } from "./types.js";

/** The typed namespace of the generated bindings. */
export type WasmModule = typeof wasm;

const WASM_FILE = "aqua-rs-sdk-core-wasm/aqua_rs_sdk_core_wasm_bg.wasm";

let ready = false;
let pending: Promise<WasmModule> | null = null;

/** `true` once `init()` / `initSync()` from this package has completed. */
export function isInitialized(): boolean {
  return ready;
}

function isNode(): boolean {
  const g = globalThis as { process?: { versions?: { node?: string } }; window?: unknown };
  return typeof g.process?.versions?.node === "string" && g.window === undefined;
}

/**
 * Locate and read the `.wasm` file in Node without a bundler: resolves the
 * package subpath through the module graph, so it works from any working
 * directory and from a consumer's `node_modules`.
 */
export async function readNodeWasm(): Promise<Uint8Array> {
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const url = import.meta.resolve(WASM_FILE);
  return new Uint8Array(await readFile(fileURLToPath(url)));
}

/**
 * Instantiate the wasm module once. Idempotent: later calls return the same
 * namespace. `input` is passed straight to the package's `init`; when
 * omitted, Node reads the file from disk and browsers fetch it relative to
 * the package's own JS.
 */
export async function init(input?: InitInput | Promise<InitInput>): Promise<WasmModule> {
  if (ready) return wasm;
  if (pending) return pending;
  pending = (async () => {
    const moduleOrPath = input ?? (isNode() ? await readNodeWasm() : undefined);
    await initWasm(moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath });
    ready = true;
    return wasm;
  })();
  try {
    return await pending;
  } catch (e) {
    pending = null;
    throw e;
  }
}

/** Synchronous variant for callers that already hold the bytes or a compiled module. */
export function initSync(module: SyncInitInput): WasmModule {
  if (!ready) {
    wasm.initSync({ module });
    ready = true;
  }
  return wasm;
}

/** The namespace, or a clear error if `init()` has not run. */
export function ensureReady(): WasmModule {
  if (!ready) {
    throw new Error(
      "aqua-core-js: wasm module not initialized; call `await init()` or `await AquaSDK.load()` first",
    );
  }
  return wasm;
}

// ── JSON boundary helpers ────────────────────────────────────────────────

export function toJson(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

export function fromJson<T>(json: string): T {
  return JSON.parse(json) as T;
}

/** Optional `Method` parameter as the wasm side expects it (bare name or `null`). */
export function methodArg(method: Method | null | undefined): string | null {
  return method ?? null;
}

/** Optional JSON parameter: `null` for absent, otherwise serialized. */
export function optionalJson(value: unknown): string | null {
  return value === undefined || value === null ? null : toJson(value);
}
