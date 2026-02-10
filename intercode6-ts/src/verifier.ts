/**
 * Signature verification for UIC barcode tickets.
 *
 * Supports two-level verification:
 * - Level 2: Uses the embedded level2PublicKey (self-contained).
 * - Level 1: Requires an externally provided public key (via options).
 *
 * Signature format is determined by header version:
 * - Header V1 (U1) → FCB V1 → structured (DER)
 * - Header V2 (U2) → FCB V2 / DOSIPAS → raw (r‖s)
 *
 * Uses Node.js crypto for ECDSA/DSA signature verification.
 */
import { verify, type KeyObject } from 'node:crypto';

import { extractSignedData, type ExtractedSignedData } from './signed-data';
import { getSigningAlgorithm, getKeyAlgorithm } from './oids';
import {
  rawSignatureToDer,
  importEcPublicKey,
  importSpkiPublicKey,
  validateEcSignatureSize,
} from './signature-utils';
import type {
  Level1KeyProvider,
  SignatureVerificationResult,
  SingleVerificationResult,
  VerifyOptions,
} from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Header V1 signatures are structured (DER), already accepted by Node.js.
 * Header V2 signatures are raw (r‖s), need conversion to DER.
 */
function signatureToDer(signature: Uint8Array, headerVersion: number): Uint8Array {
  if (headerVersion >= 2) {
    return rawSignatureToDer(signature);
  }
  // V1: already DER
  return signature;
}

function verifyWithCrypto(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: KeyObject,
  hash: string,
  headerVersion: number,
): boolean {
  const sig = signatureToDer(signature, headerVersion);
  return verify(hash, data, publicKey, Buffer.from(sig));
}

function resolvePublicKey(
  rawKey: Uint8Array | KeyObject,
  keyAlgOid?: string,
): KeyObject {
  // Already a KeyObject
  if (typeof rawKey === 'object' && 'type' in rawKey && (rawKey as KeyObject).asymmetricKeyType !== undefined) {
    return rawKey as KeyObject;
  }

  const rawBytes = rawKey as Uint8Array;
  if (!keyAlgOid) {
    throw new Error('Key algorithm OID is required when providing raw key bytes');
  }

  const keyAlg = getKeyAlgorithm(keyAlgOid);
  if (!keyAlg) {
    throw new Error(`Unknown key algorithm OID: ${keyAlgOid}`);
  }

  if (keyAlg.type === 'EC') {
    return importEcPublicKey(rawBytes);
  }

  // DSA: raw bytes are DER-encoded SPKI
  return importSpkiPublicKey(rawBytes);
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
    const keyAlg = getKeyAlgorithm(keyAlgOid);
    if (!keyAlg) {
      return { valid: false, error: `Unknown level 2 key algorithm: ${keyAlgOid}` };
    }

    // Validate raw signature size for EC keys (V2 only — V1 is DER)
    if (keyAlg.type === 'EC' && data.headerVersion >= 2) {
      const sizeError = validateEcSignatureSize(data.level2Signature);
      if (sizeError) {
        return { valid: false, error: sizeError };
      }
    }

    const publicKey = resolvePublicKey(data.level2PublicKey, keyAlgOid);
    const valid = verifyWithCrypto(
      data.level2SignedBytes,
      data.level2Signature,
      publicKey,
      sigAlg.hash,
      data.headerVersion,
    );

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

    // Validate raw signature size for EC keys (V2 only — V1 is DER)
    const keyAlgOid = data.level1KeyAlg;
    if (keyAlgOid && data.headerVersion >= 2) {
      const keyAlg = getKeyAlgorithm(keyAlgOid);
      if (keyAlg?.type === 'EC') {
        const sizeError = validateEcSignatureSize(data.level1Signature);
        if (sizeError) {
          return { valid: false, error: sizeError };
        }
      }
    }

    const resolved = resolvePublicKey(publicKey, keyAlgOid);
    const valid = verifyWithCrypto(
      data.level1DataBytes,
      data.level1Signature,
      resolved,
      sigAlg.hash,
      data.headerVersion,
    );

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
