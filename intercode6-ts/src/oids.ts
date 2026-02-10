/**
 * OID-to-algorithm mapping for UIC barcode signature verification.
 *
 * Only algorithms actually used in FCB barcodes are included.
 * FCB signatures are always structured (DER-encoded).
 *
 * | Algorithm            |
 * |----------------------|
 * | DSA with SHA-1       |
 * | DSA with SHA-224     |
 * | DSA with SHA-256     |
 * | ECDSA with SHA-256   |
 */

export interface SigningAlgorithm {
  hash: string;
  type: 'ECDSA' | 'DSA';
}

export interface KeyAlgorithm {
  type: 'EC' | 'DSA';
  curve?: string;
}

const SIGNING_ALGORITHMS: Record<string, SigningAlgorithm> = {
  // DSA with SHA-1 — FCB V1 (structured)
  '1.2.840.10040.4.3': { hash: 'SHA-1', type: 'DSA' },
  // DSA with SHA-224 — FCB V2 (raw), DOSIPAS (structured)
  '2.16.840.1.101.3.4.3.1': { hash: 'SHA-224', type: 'DSA' },
  // DSA with SHA-256 — FCB V2 (raw), DOSIPAS (structured)
  '2.16.840.1.101.3.4.3.2': { hash: 'SHA-256', type: 'DSA' },
  // ECDSA with SHA-256 — DOSIPAS (structured)
  '1.2.840.10045.4.3.2': { hash: 'SHA-256', type: 'ECDSA' },
};

const KEY_ALGORITHMS: Record<string, KeyAlgorithm> = {
  // DSA — used with DSA-512/1024/2048 across FCB V1, V2, DOSIPAS
  '1.2.840.10040.4.1': { type: 'DSA' },
  // EC P-256 (secp256r1) — used with ECDSA-P256 in DOSIPAS
  '1.2.840.10045.3.1.7': { type: 'EC', curve: 'P-256' },
};

/** Look up a signing algorithm by OID. Returns undefined if not recognized. */
export function getSigningAlgorithm(oid: string): SigningAlgorithm | undefined {
  return SIGNING_ALGORITHMS[oid];
}

/** Look up a key algorithm by OID. Returns undefined if not recognized. */
export function getKeyAlgorithm(oid: string): KeyAlgorithm | undefined {
  return KEY_ALGORITHMS[oid];
}

/** Get all known signing algorithm OIDs. */
export function getSigningAlgorithmOids(): string[] {
  return Object.keys(SIGNING_ALGORITHMS);
}

/** Get all known key algorithm OIDs. */
export function getKeyAlgorithmOids(): string[] {
  return Object.keys(KEY_ALGORITHMS);
}
