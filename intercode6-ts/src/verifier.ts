/**
 * Signature verification for UIC barcode tickets.
 *
 * Verifies Level 1 and Level 2 digital signatures using @noble/curves
 * for cross-platform support (Node.js + browser).
 *
 * - Level 2: Self-contained verification using the embedded public key.
 * - Level 1: Requires an external public key (from key management service).
 */
import { extractSignedDataBytes } from './signed-data';
import { getSigningAlgorithm, getKeyAlgorithm } from './oids';
import { verifyEcdsa } from './signature-utils';
import type {
  SignatureVerificationResult,
  SignatureLevelResult,
  VerifyOptions,
} from './types';

/**
 * Check whether a Level 2 signature is present in a UIC barcode.
 *
 * Checks for the presence of the Level 2 signature, public key,
 * and signing algorithm OID - the three fields required for
 * self-contained Level 2 verification.
 */
export function hasLevel2Signature(bytes: Uint8Array): boolean {
  try {
    const { header } = extractSignedDataBytes(bytes);
    const level2Signature = header.level2Signature as Uint8Array | undefined;
    const l2 = header.level2SignedData as Record<string, unknown>;
    const l1 = l2.level1Data as Record<string, unknown>;
    return !!(level2Signature && l1.level2PublicKey && l1.level2SigningAlg);
  } catch {
    return false;
  }
}

/**
 * Verify both Level 1 and Level 2 signatures on a UIC barcode.
 *
 * Level 2 verification uses the embedded level2PublicKey from level1Data.
 * Level 1 verification requires an external public key via options.
 *
 * @param bytes - The raw barcode payload bytes.
 * @param options - Options for Level 1 key resolution.
 * @returns Verification results for both levels.
 */
export async function verifySignatures(
  bytes: Uint8Array,
  options?: VerifyOptions,
): Promise<SignatureVerificationResult> {
  const level2 = await verifyLevel2Signature(bytes);

  let level1: SignatureLevelResult;
  if (options?.level1PublicKey) {
    level1 = await verifyLevel1Signature(bytes, options.level1PublicKey);
  } else if (options?.level1KeyProvider) {
    try {
      const { header } = extractSignedDataBytes(bytes);
      const l2 = header.level2SignedData as Record<string, unknown>;
      const l1 = l2.level1Data as Record<string, unknown>;
      const provider = {
        num: l1.securityProviderNum as number | undefined,
        ia5: l1.securityProviderIA5 as string | undefined,
      };
      const keyId = l1.keyId as number;
      const keyAlg = l1.level1KeyAlg as string | undefined;
      const publicKey = await options.level1KeyProvider.getPublicKey(provider, keyId, keyAlg);
      level1 = await verifyLevel1Signature(bytes, publicKey);
    } catch (e) {
      level1 = {
        valid: false,
        error: `Key provider error: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  } else {
    level1 = { valid: false, error: 'No Level 1 public key provided' };
  }

  return { level1, level2 };
}

/**
 * Verify only the Level 2 signature (self-contained).
 *
 * Uses the level2PublicKey embedded in level1Data and the level2Signature
 * from the header envelope.
 */
export async function verifyLevel2Signature(
  bytes: Uint8Array,
): Promise<SignatureLevelResult> {
  try {
    const { level2SignedBytes, header } = extractSignedDataBytes(bytes);

    const level2Signature = header.level2Signature as Uint8Array | undefined;
    if (!level2Signature || level2Signature.length === 0) {
      return { valid: false, error: 'Missing Level 2 signature' };
    }

    const l2 = header.level2SignedData as Record<string, unknown>;
    const l1 = l2.level1Data as Record<string, unknown>;

    const signingAlgOid = l1.level2SigningAlg as string | undefined;
    if (!signingAlgOid) {
      return { valid: false, error: 'Missing Level 2 signing algorithm OID' };
    }

    const sigAlg = getSigningAlgorithm(signingAlgOid);
    if (!sigAlg) {
      return { valid: false, error: `Unknown signing algorithm OID: ${signingAlgOid}` };
    }

    if (sigAlg.type !== 'ECDSA') {
      return {
        valid: false,
        error: `Unsupported signature type for Level 2: ${sigAlg.type} (only ECDSA supported)`,
        algorithm: `${sigAlg.type}-${sigAlg.hash}`,
      };
    }

    const keyAlgOid = l1.level2KeyAlg as string | undefined;
    if (!keyAlgOid) {
      return { valid: false, error: 'Missing Level 2 key algorithm OID' };
    }

    const keyAlg = getKeyAlgorithm(keyAlgOid);
    if (!keyAlg) {
      return { valid: false, error: `Unknown key algorithm OID: ${keyAlgOid}` };
    }

    if (keyAlg.type !== 'EC') {
      return {
        valid: false,
        error: `Unsupported key type for Level 2: ${keyAlg.type} (only EC supported)`,
        algorithm: `${sigAlg.type}-${sigAlg.hash}`,
      };
    }

    const publicKey = l1.level2PublicKey as Uint8Array | undefined;
    if (!publicKey || publicKey.length === 0) {
      return { valid: false, error: 'Missing Level 2 public key' };
    }

    const algorithm = `${sigAlg.type}-${sigAlg.hash} (${keyAlg.curve})`;

    const valid = verifyEcdsa(level2SignedBytes, level2Signature, publicKey, sigAlg, keyAlg);
    return { valid, algorithm };
  } catch (e) {
    return {
      valid: false,
      error: `Verification error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * Verify only the Level 1 signature.
 *
 * Requires the Level 1 public key (not embedded in the barcode).
 */
export async function verifyLevel1Signature(
  bytes: Uint8Array,
  publicKey: Uint8Array,
): Promise<SignatureLevelResult> {
  try {
    const { level1DataBytes, header } = extractSignedDataBytes(bytes);

    const l2 = header.level2SignedData as Record<string, unknown>;
    const l1 = l2.level1Data as Record<string, unknown>;

    const level1Signature = l2.level1Signature as Uint8Array | undefined;
    if (!level1Signature || level1Signature.length === 0) {
      return { valid: false, error: 'Missing Level 1 signature' };
    }

    const signingAlgOid = l1.level1SigningAlg as string | undefined;
    if (!signingAlgOid) {
      return { valid: false, error: 'Missing Level 1 signing algorithm OID' };
    }

    const sigAlg = getSigningAlgorithm(signingAlgOid);
    if (!sigAlg) {
      return { valid: false, error: `Unknown signing algorithm OID: ${signingAlgOid}` };
    }

    if (sigAlg.type !== 'ECDSA') {
      return {
        valid: false,
        error: `Unsupported signature type for Level 1: ${sigAlg.type} (only ECDSA supported)`,
        algorithm: `${sigAlg.type}-${sigAlg.hash}`,
      };
    }

    const keyAlgOid = l1.level1KeyAlg as string | undefined;
    if (!keyAlgOid) {
      return { valid: false, error: 'Missing Level 1 key algorithm OID' };
    }

    const keyAlg = getKeyAlgorithm(keyAlgOid);
    if (!keyAlg) {
      return { valid: false, error: `Unknown key algorithm OID: ${keyAlgOid}` };
    }

    if (keyAlg.type !== 'EC') {
      return {
        valid: false,
        error: `Unsupported key type for Level 1: ${keyAlg.type} (only EC supported)`,
        algorithm: `${sigAlg.type}-${sigAlg.hash}`,
      };
    }

    const algorithm = `${sigAlg.type}-${sigAlg.hash} (${keyAlg.curve})`;

    const valid = verifyEcdsa(level1DataBytes, level1Signature, publicKey, sigAlg, keyAlg);
    return { valid, algorithm };
  } catch (e) {
    return {
      valid: false,
      error: `Verification error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}
