/**
 * Shared test setup: one initialized SDK per worker, plus small helpers.
 */

import { AquaSDK, init, wrap, isVerified } from "../src/index.js";
import type { Tree, VerificationResult } from "../src/index.js";

let sdkPromise: Promise<AquaSDK> | null = null;

/** Lazily initialize the wasm module and construct a default SDK. */
export function sdk(): Promise<AquaSDK> {
  sdkPromise ??= (async () => {
    await init();
    return new AquaSDK();
  })();
  return sdkPromise;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const HELLO = utf8("hello aqua from vitest");
export const HELLO_NAME = "hello.txt";

export function helloFiles() {
  return [{ file_name: HELLO_NAME, file_content: Array.from(HELLO), path: HELLO_NAME }];
}

export { wrap, isVerified };

export function revisionCount(tree: Tree): number {
  return Object.keys(tree.revisions).length;
}

export function outcomeSummary(r: VerificationResult): string {
  return JSON.stringify(r.outcome);
}
