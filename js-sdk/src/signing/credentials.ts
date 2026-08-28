/**
 * In-wasm signing with `SigningCredentials`: the key material is handed to
 * the core's own signers (`signAquaTree`). Not an `AquaSigner`, because no
 * message leaves the module; use it when the secret is available in memory
 * and no wallet is involved.
 */

import { hexToBytes } from "../bytes.js";
import type { AquaSDK } from "../core.js";
import { didFromEd25519SecretKey, didFromP256SecretKey, generateEd25519 } from "../did.js";
import type { AquaOperationData, Method, SigningCredentials, WrapperLike } from "../types.js";

export class CredentialsSigner {
  /**
   * The DID `signAquaTree` will record, when derivable here: `did:key` for
   * Ed25519 and P-256 secrets. secp256k1 (`did:pkh:eip155:1:0x...`) is
   * derived inside the core at signing time and is `undefined` here.
   */
  readonly did: string | undefined;

  constructor(readonly credentials: SigningCredentials) {
    if ("did_key" in credentials) {
      this.did = didFromEd25519SecretKey(hexToBytes(credentials.did_key));
    } else if ("p256_key" in credentials) {
      this.did = didFromP256SecretKey(hexToBytes(credentials.p256_key));
    } else {
      this.did = undefined;
    }
  }

  /** Fresh Ed25519 credentials from the host CSPRNG. */
  static generateEd25519(): CredentialsSigner {
    return new CredentialsSigner({ did_key: generateEd25519().secret });
  }

  /** Sign the wrapper's target revision (tip by default) with these credentials. */
  sign(sdk: AquaSDK, wrapper: WrapperLike, method?: Method | null, ident?: string | null): Promise<AquaOperationData> {
    return sdk.signAquaTree(wrapper, this.credentials, method, ident);
  }
}
