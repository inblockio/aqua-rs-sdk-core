/**
 * EIP-191 signer over an EIP-1193 provider (MetaMask, or any injected
 * wallet exposing `request`). No ethers dependency: `personal_sign` is a
 * single JSON-RPC call and the wallet does the hashing.
 *
 * Contract (from `prepareSignature`'s doc comment): the wallet signs the
 * prepared `message` string with `personal_sign`, producing a 65-byte
 * `r || s || v` signature; the public identifier is the 20-byte address and
 * the `signer` DID is `did:pkh:eip155:<chainId>:<address>`. The core
 * verifier recovers the address from the signature and compares it, byte
 * for byte, with both.
 */

import { bytesToHex, toBytes, toText } from "../bytes.js";
import type { Bytes, SignatureValue } from "../types.js";
import type { AquaSigner } from "./signer.js";

/** The subset of EIP-1193 this signer uses. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export class MetaMaskSigner implements AquaSigner {
  readonly signatureType = "ethereum:eip-191" as const;
  readonly signer: string;

  /**
   * `address` must be one of the provider's unlocked accounts (any case;
   * the core compares raw address bytes). `chainId` is decimal.
   */
  constructor(
    private readonly provider: Eip1193Provider,
    readonly address: string,
    readonly chainId: number,
  ) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`not a 20-byte hex address: ${address}`);
    this.signer = `did:pkh:eip155:${chainId}:${address}`;
  }

  /** Whether an injected provider is present (`window.ethereum`). */
  static isAvailable(): boolean {
    return injectedProvider() !== undefined;
  }

  /**
   * Request accounts and the chain id from the provider (default:
   * `window.ethereum`) and build a signer for the first account.
   */
  static async connect(provider: Eip1193Provider | undefined = injectedProvider()): Promise<MetaMaskSigner> {
    if (!provider) throw new Error("no EIP-1193 provider: pass one explicitly or install a wallet extension");
    const accounts = (await provider.request({ method: "eth_requestAccounts" })) as unknown;
    const address = Array.isArray(accounts) ? (accounts[0] as string | undefined) : undefined;
    if (!address) throw new Error("wallet returned no accounts");
    const chainHex = (await provider.request({ method: "eth_chainId" })) as string;
    const chainId = Number.parseInt(chainHex, 16);
    if (!Number.isFinite(chainId)) throw new Error(`wallet returned an invalid chain id: ${chainHex}`);
    return new MetaMaskSigner(provider, address, chainId);
  }

  async sign(message: Bytes): Promise<SignatureValue> {
    // personal_sign takes the message as hex bytes; the wallet prefixes and
    // keccak-hashes it. The prepared message is ASCII JSON, so its UTF-8
    // byte length equals what the core uses in the prefix.
    const hexMessage = bytesToHex(toBytes(toText(message)));
    const signature = (await this.provider.request({
      method: "personal_sign",
      params: [hexMessage, this.address],
    })) as string;
    if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
      throw new Error(`wallet returned an invalid personal_sign result: ${String(signature)}`);
    }
    return {
      signature_type: "ethereum:eip-191",
      signature: normalizeV(signature),
      signature_public_identifier: this.address,
    };
  }
}

/** Some wallets return `v` as 0/1; the core accepts both but 27/28 is the EIP-191 convention. */
function normalizeV(signature: string): string {
  const v = parseInt(signature.slice(-2), 16);
  if (v === 0 || v === 1) return signature.slice(0, -2) + (v + 27).toString(16);
  return signature;
}

function injectedProvider(): Eip1193Provider | undefined {
  const g = globalThis as { ethereum?: Eip1193Provider };
  return g.ethereum && typeof g.ethereum.request === "function" ? g.ethereum : undefined;
}
