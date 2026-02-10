/**
 * Signature verification for UIC barcode tickets.
 *
 * Supports two-level verification:
 * - Level 2: Uses the embedded level2PublicKey (self-contained).
 * - Level 1: Requires an externally provided public key (via options).
 *
 * FCB signatures are always structured (DER-encoded), for both static
 * barcodes (FCB V1/V2/V3) and dynamic barcodes (DOSIPAS).
 *
 * Uses Node.js crypto for ECDSA/DSA signature verification.
 */
import { verify, type KeyObject } from 'node:crypto';

import { extractSignedData } from './signed-data';
import { getSigningAlgorithm, getKeyAlgorithm } from './oids';
import { importSpkiPublicKey } from './signature-utils';
import type {
  SignatureVerificationResult,
  SingleVerificationResult,
  VerifyOptions,
} from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function resolvePublicKey(
  rawKey: Uint8Array | KeyObject,
): KeyObject {
  if (typeof rawKey === 'object' && 'type' in rawKey && (rawKey as KeyObject).asymmetricKeyType !== undefined) {
    return rawKey as KeyObject;
  }

  // Public keys in FCB barcodes are DER-encoded SPKI structures.
  return importSpkiPublicKey(rawKey as Uint8Array);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify the Level 2 signature on a UIC barcode.
 *
 * This is self-contained: the level2PublicKey is embedded in level1Data.
 * No external key is needed.
 *
 * @param bytes - The raw barcode payload bytes.
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel2Signature(
  bytes: Uint8Array,
): Promise<SingleVerificationResult> {
  try {
    const data = extractSignedData(bytes);

    if (!data.level2Signature) {
      return { valid: false, error: 'Missing level 2 signature' };
    }
    if (!data.level2PublicKey) {
      return { valid: false, error: 'Missing level 2 public key' };
    }
    if (!data.level2SigningAlg) {
      return { valid: false, error: 'Missing level 2 signing algorithm OID' };
    }

    const sigAlg = getSigningAlgorithm(data.level2SigningAlg);
    if (!sigAlg) {
      return {
        valid: false,
        error: `Unknown level 2 signing algorithm: ${data.level2SigningAlg}`,
      };
    }

    const keyAlgOid = data.level2KeyAlg;
    if (!keyAlgOid) {
      return { valid: false, error: 'Missing level 2 key algorithm OID' };
    }
    if (!getKeyAlgorithm(keyAlgOid)) {
      return { valid: false, error: `Unknown level 2 key algorithm: ${keyAlgOid}` };
    }

    const publicKey = resolvePublicKey(data.level2PublicKey);
    // FCB signatures are always structured (DER) — pass directly to verify
    const valid = verify(sigAlg.hash, data.level2SignedBytes, publicKey, Buffer.from(data.level2Signature));

    return { valid, algorithm: `${sigAlg.type} with ${sigAlg.hash}` };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Verify the Level 1 signature on a UIC barcode.
 *
 * Requires an externally provided public key.
 *
 * @param bytes - The raw barcode payload bytes.
 * @param publicKey - The Level 1 public key (raw bytes or KeyObject).
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel1Signature(
  bytes: Uint8Array,
  publicKey: Uint8Array | KeyObject,
): Promise<SingleVerificationResult> {
  try {
    const data = extractSignedData(bytes);

    if (!data.level1Signature) {
      return { valid: false, error: 'Missing level 1 signature' };
    }
    if (!data.level1SigningAlg) {
      return { valid: false, error: 'Missing level 1 signing algorithm OID' };
    }

    const sigAlg = getSigningAlgorithm(data.level1SigningAlg);
    if (!sigAlg) {
      return {
        valid: false,
        error: `Unknown level 1 signing algorithm: ${data.level1SigningAlg}`,
      };
    }

    const resolved = resolvePublicKey(publicKey);
    // FCB signatures are always structured (DER) — pass directly to verify
    const valid = verify(sigAlg.hash, data.level1DataBytes, resolved, Buffer.from(data.level1Signature));

    return { valid, algorithm: `${sigAlg.type} with ${sigAlg.hash}` };
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Verify both Level 1 and Level 2 signatures on a UIC barcode.
 *
 * Level 2 verification uses the embedded level2PublicKey (always attempted).
 * Level 1 verification requires an external key via options.
 *
 * @param bytes - The raw barcode payload bytes.
 * @param options - Options including level 1 key provider or explicit key.
 * @returns Verification results for both levels.
 */
export async function verifySignatures(
  bytes: Uint8Array,
  options?: VerifyOptions,
): Promise<SignatureVerificationResult> {
  const level2 = await verifyLevel2Signature(bytes);

  let level1: SingleVerificationResult;

  if (options?.level1PublicKey) {
    level1 = await verifyLevel1Signature(bytes, options.level1PublicKey);
  } else if (options?.level1KeyProvider) {
    try {
      const data = extractSignedData(bytes);
      const provider = {
        num: data.securityProviderNum,
        ia5: data.securityProviderIA5,
      };
      const keyId = data.keyId;
      if (keyId === undefined) {
        level1 = { valid: false, error: 'Missing keyId for level 1 key lookup' };
      } else {
        const key = await options.level1KeyProvider.getPublicKey(
          provider,
          keyId,
          data.level1KeyAlg,
        );
        level1 = await verifyLevel1Signature(bytes, key);
      }
    } catch (err) {
      level1 = {
        valid: false,
        error: `Level 1 key provider error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else {
    level1 = { valid: false, error: 'No level 1 public key provided' };
  }

  return { level1, level2 };
}
