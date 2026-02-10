/**
 * Public key import utilities for UIC barcode signature verification.
 *
 * FCB public keys are stored as DER-encoded SubjectPublicKeyInfo (SPKI)
 * structures in the barcode. This module imports them into Node.js KeyObjects.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';

/**
 * Import a DER-encoded SubjectPublicKeyInfo (SPKI) public key.
 *
 * Both EC and DSA public keys in FCB barcodes are stored as full SPKI blobs.
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
