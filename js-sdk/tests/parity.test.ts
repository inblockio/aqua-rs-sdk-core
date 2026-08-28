/**
 * Export parity: every export of the generated wasm bindings is wrapped by
 * `AquaSDK` or a module-level function of this package. The list is parsed
 * from the package's `.d.ts` at test time so a new or renamed Rust export
 * fails here instead of silently going unwrapped.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";
import { AquaSDK } from "../src/index.js";
import { sdk } from "./helpers.js";

const DTS = new URL("../../wasm/pkg/aqua_rs_sdk_core_wasm.d.ts", import.meta.url);

/** Loader / lifecycle names that are not API. */
const NOT_API = new Set(["init_panic_hook", "initSync", "free", "constructor", "__wbg_init"]);

/** Exports whose wrapper is not a same-named function. */
const RENAMED: Record<string, () => boolean> = {
  // `withOptions` is the `AquaSDK` constructor's `options` argument.
  withOptions: () => new AquaSDK({ hash_type: "blake3_256" }).hashType() === "BLAKE3-256",
};

function parseExports(text: string): { classMembers: string[]; freeFunctions: string[] } {
  const freeFunctions = [...text.matchAll(/^export function (\w+)\s*\(/gm)].map((m) => m[1]!);
  const classBody = text.match(/export class AquafierWasm \{([\s\S]*?)\n\}/)?.[1] ?? "";
  const classMembers = [...classBody.matchAll(/^\s{4}(?:static\s+)?(\w+)\s*\(/gm)].map((m) => m[1]!);
  return { classMembers, freeFunctions };
}

describe("wasm export parity", () => {
  const text = readFileSync(DTS, "utf8");
  const { classMembers, freeFunctions } = parseExports(text);

  it("parses a plausible export list from the generated .d.ts", () => {
    expect(classMembers.length).toBeGreaterThanOrEqual(20);
    expect(freeFunctions.length).toBeGreaterThanOrEqual(30);
    // Count in WASM_EXPORTS.md at the time of writing: 32 classes + functions.
    expect(freeFunctions.length + 1).toBe(32);
  });

  it("every AquafierWasm member is a method of AquaSDK", async () => {
    await sdk();
    const missing = classMembers
      .filter((name) => !NOT_API.has(name))
      .filter((name) => (name in RENAMED ? !RENAMED[name]!() : typeof AquaSDK.prototype[name as keyof AquaSDK] !== "function"));
    expect(missing).toEqual([]);
  });

  it("every free function is exported by the package", () => {
    const missing = freeFunctions
      .filter((name) => !NOT_API.has(name))
      .filter((name) => typeof (api as Record<string, unknown>)[name] !== "function");
    expect(missing).toEqual([]);
  });

  it("the runtime module exposes what the .d.ts declares", async () => {
    const aq = await sdk();
    const runtime = aq.wasm as unknown as Record<string, unknown>;
    for (const name of freeFunctions.filter((n) => !NOT_API.has(n))) {
      expect(typeof runtime[name], name).toBe("function");
    }
    for (const name of classMembers.filter((n) => !NOT_API.has(n) && n !== "withOptions")) {
      expect(typeof (aq.wasm.AquafierWasm.prototype as unknown as Record<string, unknown>)[name], name).toBe("function");
    }
  });
});
