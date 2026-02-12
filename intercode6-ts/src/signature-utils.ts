/**
 * Signature format utilities for UIC barcode verification.
 *
 * Handles ECDSA signature verification using @noble/curves, which works
 * in both Node.js and browser environments.
 */
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import type { SigningAlgorithm, KeyAlgorithm } from './oids';

// Known SPKI prefixes for EC curves (AlgorithmIdentifier + BIT STRING header)
// P-256 SPKI: 91 bytes total, prefix is 26 bytes before the 65-byte uncompressed point
const P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);
// P-384 SPKI: 120 bytes total, prefix is 24 bytes before the 97-byte uncompressed point
const P384_SPKI_PREFIX = new Uint8Array([
  0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
]);
// P-521 SPKI: 158 bytes total, prefix is 26 bytes before the 133-byte uncompressed point
const P521_SPKI_PREFIX = new Uint8Array([
  0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00,
]);

function startsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) return false;
  }
  return true;
}

/**
 * Normalize an EC public key that may be in SubjectPublicKeyInfo (SPKI) format.
 * Returns the raw EC point bytes (04||x||y or 02/03||x).
 *
 * Handles:
 * - Raw EC point (starts with 04, 02, or 03) → returned as-is
 * - SPKI-wrapped key (starts with 30) → unwrapped to raw point
 */
export function normalizeEcPublicKey(key: Uint8Array): Uint8Array {
  // Raw EC point: uncompressed (04) or compressed (02/03)
  if (key[0] === 0x04 || key[0] === 0x02 || key[0] === 0x03) {
    return key;
  }

  // SPKI-wrapped: strip the known prefix
  if (startsWith(key, P256_SPKI_PREFIX)) return key.subarray(P256_SPKI_PREFIX.length);
  if (startsWith(key, P384_SPKI_PREFIX)) return key.subarray(P384_SPKI_PREFIX.length);
  if (startsWith(key, P521_SPKI_PREFIX)) return key.subarray(P521_SPKI_PREFIX.length);

  // Unknown format, return as-is and let verification fail naturally
  return key;
}

/**
 * Convert an ECDSA signature from DER format to compact (r || s) format.
 *
 * DER format: 30 <len> 02 <rlen> <r> 02 <slen> <s>
 * Compact format: r (padded to byteLen) || s (padded to byteLen)
 *
 * @noble/curves v2 only accepts compact format in verify().
 */
function derToCompact(sig: Uint8Array, byteLen: number): Uint8Array {
  if (sig[0] !== 0x30) {
    // Not DER, assume already compact
    return sig;
  }

  let pos = 2; // skip SEQUENCE tag + length

  // Read r
  if (sig[pos] !== 0x02) throw new Error('Expected INTEGER tag for r');
  const rLen = sig[pos + 1];
  pos += 2;
  let r = sig.subarray(pos, pos + rLen);
  pos += rLen;

  // Read s
  if (sig[pos] !== 0x02) throw new Error('Expected INTEGER tag for s');
  const sLen = sig[pos + 1];
  pos += 2;
  let s = sig.subarray(pos, pos + sLen);

  // Strip leading zero padding from DER integers
  if (r.length > byteLen && r[0] === 0) r = r.subarray(1);
  if (s.length > byteLen && s[0] === 0) s = s.subarray(1);

  // Left-pad to exact byte length
  const compact = new Uint8Array(byteLen * 2);
  compact.set(r, byteLen - r.length);
  compact.set(s, byteLen * 2 - s.length);
  return compact;
}

/**
 * Normalize an ECDSA signature to compact (r || s) format.
 * Handles both DER-encoded and raw compact signatures.
 */
function normalizeSignature(sig: Uint8Array, curve: string): Uint8Array {
  const byteLens: Record<string, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };
  const byteLen = byteLens[curve];
  if (!byteLen) throw new Error(`Unknown curve for signature normalization: ${curve}`);

  // Already compact format
  if (sig.length === byteLen * 2) return sig;

  // DER format (starts with 0x30 SEQUENCE)
  if (sig[0] === 0x30) return derToCompact(sig, byteLen);

  // Unknown format, return as-is
  return sig;
}

/**
 * Hash the message using the specified hash algorithm.
 */
function hashMessage(message: Uint8Array, hash: string): Uint8Array {
  switch (hash) {
    case 'SHA-256': return sha256(message);
    case 'SHA-384': return sha384(message);
    case 'SHA-512': return sha512(message);
    default: throw new Error(`Unsupported hash algorithm: ${hash}`);
  }
}

/**
 * Verify an ECDSA signature using @noble/curves.
 *
 * @param message - The data that was signed (will be hashed with sigAlg.hash).
 * @param signature - Raw (r || s) concatenated signature bytes.
 * @param publicKey - Raw EC public key (uncompressed 04||x||y or compressed 02/03||x).
 * @param sigAlg - The signing algorithm info (hash + type).
 * @param keyAlg - The key algorithm info (curve).
 * @returns true if valid, false otherwise.
 */
export function verifyEcdsa(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  sigAlg: SigningAlgorithm,
  keyAlg: KeyAlgorithm,
): boolean {
  if (!keyAlg.curve) {
    throw new Error('Key algorithm has no curve specified');
  }

  // Normalize public key (unwrap SPKI) and signature (DER → compact)
  const rawKey = normalizeEcPublicKey(publicKey);
  const rawSig = normalizeSignature(signature, keyAlg.curve);

  // Pre-hash the message with the specified algorithm
  const msgHash = hashMessage(message, sigAlg.hash);

  switch (keyAlg.curve) {
    case 'P-256':
      return p256.verify(rawSig, msgHash, rawKey, { prehash: false });
    case 'P-384':
      return p384.verify(rawSig, msgHash, rawKey, { prehash: false });
    case 'P-521':
      return p521.verify(rawSig, msgHash, rawKey, { prehash: false });
    default:
      throw new Error(`Unsupported curve: ${keyAlg.curve}`);
  }
}
