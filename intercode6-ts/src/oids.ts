/**
 * OID-to-algorithm mapping for UIC barcode signature verification.
 *
 * Maps signing algorithm OIDs to their hash function and signature type,
 * and key algorithm OIDs to their curve or key type.
 */

export interface SigningAlgorithm {
  hash: string;
  type: 'ECDSA' | 'DSA' | 'RSA';
}

export interface KeyAlgorithm {
  type: 'EC' | 'RSA';
  curve?: string;
}

const SIGNING_ALGORITHMS: Record<string, SigningAlgorithm> = {
  '1.2.840.10045.4.3.2': { hash: 'SHA-256', type: 'ECDSA' },
  '1.2.840.10045.4.3.3': { hash: 'SHA-384', type: 'ECDSA' },
  '1.2.840.10045.4.3.4': { hash: 'SHA-512', type: 'ECDSA' },
  '2.16.840.1.101.3.4.3.1': { hash: 'SHA-224', type: 'DSA' },
  '2.16.840.1.101.3.4.3.2': { hash: 'SHA-256', type: 'DSA' },
  '1.2.840.113549.1.1.11': { hash: 'SHA-256', type: 'RSA' },
};

const KEY_ALGORITHMS: Record<string, KeyAlgorithm> = {
  '1.2.840.10045.3.1.7': { type: 'EC', curve: 'P-256' },
  '1.3.132.0.34': { type: 'EC', curve: 'P-384' },
  '1.3.132.0.35': { type: 'EC', curve: 'P-521' },
  '1.2.840.113549.1.1.1': { type: 'RSA' },
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
