/**
 * Signature format conversion and public key import utilities.
 *
 * UIC barcodes use two signature formats depending on the process:
 * - Raw (r ‖ s): Used by FCB V2 (TLB/FCB V2)
 * - Structured (DER): Used by FCB V1 and DOSIPAS
 *
 * Node.js crypto.verify() expects DER-encoded signatures in all cases.
 * This module provides detection, conversion, and key import helpers.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';

// ---------------------------------------------------------------------------
// DER signature detection
// ---------------------------------------------------------------------------

/**
 * Detect whether a signature is already in DER (structured) format.
 *
 * DER ECDSA/DSA signatures start with 0x30 (SEQUENCE tag).
 * Raw (r‖s) signatures start with arbitrary bytes.
 */
export function isDerSignature(signature: Uint8Array): boolean {
  if (signature.length < 2) return false;
  // SEQUENCE tag = 0x30, followed by length
  if (signature[0] !== 0x30) return false;
  // Basic sanity: the declared length should roughly match the actual data
  const declaredLen = signature[1];
  // For short-form DER length (≤127), total = 2 + declaredLen
  if (declaredLen <= 127) {
    return signature.length === 2 + declaredLen;
  }
  // Long-form length (unlikely for signatures but be safe)
  return true;
}

// ---------------------------------------------------------------------------
// DER integer encoding
// ---------------------------------------------------------------------------

/**
 * Encode a big-endian unsigned integer as a DER INTEGER.
 * Strips leading zeros but preserves one if the value is zero.
 * Adds a 0x00 pad byte if the high bit is set (to keep the value positive).
 */
function derEncodeInteger(value: Uint8Array): Uint8Array {
  // Strip leading zeros (keep at least 1 byte)
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  const trimmed = value.subarray(start);
  const needsPad = (trimmed[0] & 0x80) !== 0;
  const len = trimmed.length + (needsPad ? 1 : 0);
  const buf = new Uint8Array(2 + len);
  buf[0] = 0x02; // INTEGER tag
  buf[1] = len;
  if (needsPad) buf[2] = 0x00;
  buf.set(trimmed, 2 + (needsPad ? 1 : 0));
  return buf;
}

// ---------------------------------------------------------------------------
// Raw ↔ DER signature conversion
// ---------------------------------------------------------------------------

/**
 * Convert a raw (r ‖ s) ECDSA/DSA signature to DER-encoded format.
 *
 * Raw format: r (N bytes) ‖ s (N bytes), total = 2N bytes.
 * DER format: SEQUENCE { INTEGER r, INTEGER s }.
 *
 * @param raw - The raw concatenated signature bytes.
 * @returns DER-encoded signature.
 */
export function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  if (raw.length === 0 || raw.length % 2 !== 0) {
    throw new Error(
      `Invalid raw signature length ${raw.length}: must be even and non-zero`,
    );
  }
  const half = raw.length / 2;
  const r = raw.subarray(0, half);
  const s = raw.subarray(half);

  const rDer = derEncodeInteger(r);
  const sDer = derEncodeInteger(s);

  const innerLen = rDer.length + sDer.length;
  const seq = new Uint8Array(2 + innerLen);
  seq[0] = 0x30; // SEQUENCE tag
  seq[1] = innerLen;
  seq.set(rDer, 2);
  seq.set(sDer, 2 + rDer.length);
  return seq;
}

/**
 * Ensure a signature is in DER format for Node.js crypto.verify().
 *
 * If the signature is already DER (structured), returns it unchanged.
 * If it is raw (r‖s), converts to DER.
 */
export function ensureDerSignature(signature: Uint8Array): Uint8Array {
  if (isDerSignature(signature)) {
    return signature;
  }
  return rawSignatureToDer(signature);
}

// ---------------------------------------------------------------------------
// SPKI DER construction for EC public keys
// ---------------------------------------------------------------------------

/** OID for ecPublicKey (1.2.840.10045.2.1) in DER encoding. */
const EC_PUBLIC_KEY_OID = new Uint8Array([
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
]);

/** Named curve OID for P-256 (secp256r1) in DER encoding. */
const P256_CURVE_OID = new Uint8Array([
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
]);

/**
 * Build a SubjectPublicKeyInfo (SPKI) DER structure wrapping a raw EC public
 * key point.
 *
 * The SPKI structure is:
 *   SEQUENCE {
 *     SEQUENCE { OID ecPublicKey, OID namedCurve }
 *     BIT STRING (public key point)
 *   }
 */
function buildEcSpkiDer(rawPoint: Uint8Array): Uint8Array {
  // AlgorithmIdentifier SEQUENCE: ecPublicKey OID + P-256 curve OID
  const algIdInnerLen = EC_PUBLIC_KEY_OID.length + P256_CURVE_OID.length;
  const algId = new Uint8Array(2 + algIdInnerLen);
  algId[0] = 0x30; // SEQUENCE
  algId[1] = algIdInnerLen;
  algId.set(EC_PUBLIC_KEY_OID, 2);
  algId.set(P256_CURVE_OID, 2 + EC_PUBLIC_KEY_OID.length);

  // BIT STRING wrapping the public key point
  // BIT STRING = tag(1) + length(1+) + unused-bits(1) + content
  const bitStringLen = 1 + rawPoint.length; // 1 byte for unused-bits count
  const bitString = new Uint8Array(2 + bitStringLen);
  bitString[0] = 0x03; // BIT STRING tag
  bitString[1] = bitStringLen;
  bitString[2] = 0x00; // unused bits = 0
  bitString.set(rawPoint, 3);

  // Outer SEQUENCE
  const outerLen = algId.length + bitString.length;
  const spki = new Uint8Array(2 + outerLen);
  spki[0] = 0x30; // SEQUENCE
  spki[1] = outerLen;
  spki.set(algId, 2);
  spki.set(bitString, 2 + algId.length);

  return spki;
}

/**
 * Import a raw EC P-256 public key point as a Node.js KeyObject.
 *
 * Accepts both uncompressed (0x04 prefix) and compressed (0x02/0x03 prefix)
 * points. Node.js handles decompression internally.
 *
 * @param rawPoint - The raw EC public key bytes.
 * @returns A Node.js KeyObject for use with crypto.verify().
 */
export function importEcPublicKey(rawPoint: Uint8Array): KeyObject {
  const spki = buildEcSpkiDer(rawPoint);
  return createPublicKey({
    key: Buffer.from(spki),
    format: 'der',
    type: 'spki',
  });
}

/**
 * Import a DER-encoded SubjectPublicKeyInfo (SPKI) public key.
 *
 * Used for DSA public keys which are stored as full SPKI blobs in the barcode.
 *
 * @param spkiDer - The DER-encoded SPKI public key bytes.
 * @returns A Node.js KeyObject for use with crypto.verify().
 */
export function importSpkiPublicKey(spkiDer: Uint8Array): KeyObject {
  return createPublicKey({
    key: Buffer.from(spkiDer),
    format: 'der',
    type: 'spki',
  });
}

// ---------------------------------------------------------------------------
// Signature size validation
// ---------------------------------------------------------------------------

/** Expected raw signature size (r ‖ s) for ECDSA P-256: 32 + 32 = 64 bytes. */
const P256_RAW_SIGNATURE_SIZE = 64;

/**
 * Validate the size of a raw ECDSA P-256 signature.
 * Returns an error message if invalid, or undefined if valid.
 */
export function validateEcSignatureSize(
  signature: Uint8Array,
): string | undefined {
  if (isDerSignature(signature)) return undefined; // DER is variable-length, skip
  if (signature.length !== P256_RAW_SIGNATURE_SIZE) {
    return `Expected ${P256_RAW_SIGNATURE_SIZE}-byte raw signature for P-256, got ${signature.length} bytes`;
  }
  return undefined;
}
