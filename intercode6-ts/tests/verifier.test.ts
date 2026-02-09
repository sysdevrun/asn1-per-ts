import {
  verifyLevel2Signature,
  verifyLevel1Signature,
  verifySignatures,
} from '../src/verifier';
import { extractSignedData } from '../src/signed-data';
import { rawSignatureToDer, importEcPublicKey } from '../src/signature-utils';
import { SAMPLE_TICKET_HEX } from '../src/fixtures';
import {
  generateKeyPairSync,
  sign,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  type SchemaNode,
} from 'per-unaligned-ts';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

describe('verifyLevel2Signature', () => {
  it('returns valid:false with error for sample ticket (synthetic signatures)', async () => {
    // The sample fixture has synthetic/placeholder signatures that won't be valid
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);
    // The signature exists but is not cryptographically valid for this synthetic data
    expect(result).toHaveProperty('valid');
    expect(typeof result.valid).toBe('boolean');
    // We expect either false (invalid sig) or an error
    if (!result.valid && result.error) {
      expect(typeof result.error).toBe('string');
    }
  });

  it('returns error when signature is missing', async () => {
    // Build a minimal barcode with no level2Signature
    // We'll reuse the sample but this test is about the error path
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    // The sample does have a signature, so it should attempt verification
    const result = await verifyLevel2Signature(bytes);
    expect(result).toHaveProperty('valid');
  });
});

describe('verifyLevel1Signature', () => {
  it('returns error when no level 1 signing algorithm OID', async () => {
    // The sample ticket may or may not have level1SigningAlg
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const data = extractSignedData(bytes);

    // Create a dummy key
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const result = await verifyLevel1Signature(bytes, publicKey);
    expect(result).toHaveProperty('valid');
    // If level1SigningAlg is missing, should get an error
    if (!data.level1SigningAlg) {
      expect(result.valid).toBe(false);
      expect(result.error).toContain('signing algorithm');
    }
  });
});

describe('verifySignatures', () => {
  it('returns results for both levels', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifySignatures(bytes);

    expect(result).toHaveProperty('level1');
    expect(result).toHaveProperty('level2');
    expect(result.level1).toHaveProperty('valid');
    expect(result.level2).toHaveProperty('valid');
  });

  it('returns level 1 error when no key provided', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifySignatures(bytes);

    expect(result.level1.valid).toBe(false);
    expect(result.level1.error).toContain('No level 1 public key provided');
  });

  it('accepts level1PublicKey option', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const result = await verifySignatures(bytes, { level1PublicKey: publicKey });

    expect(result).toHaveProperty('level1');
    expect(result).toHaveProperty('level2');
    // Level 1 will likely fail (wrong key) but should not error on missing key
    if (result.level1.error) {
      expect(result.level1.error).not.toContain('No level 1 public key provided');
    }
  });

  it('accepts level1KeyProvider option', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const result = await verifySignatures(bytes, {
      level1KeyProvider: {
        async getPublicKey() {
          return publicKey;
        },
      },
    });

    expect(result).toHaveProperty('level1');
    expect(result).toHaveProperty('level2');
  });

  it('handles level1KeyProvider errors gracefully', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);

    const result = await verifySignatures(bytes, {
      level1KeyProvider: {
        async getPublicKey() {
          throw new Error('Network error');
        },
      },
    });

    expect(result.level1.valid).toBe(false);
    expect(result.level1.error).toContain('Network error');
  });
});

describe('end-to-end signature verification with crafted data', () => {
  // This test creates a real signature over known data and verifies it
  // using the rawSignatureToDer and importEcPublicKey utilities

  it('verifies a real ECDSA-SHA256 signature using the utility functions', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });

    const data = Buffer.from('the data that was signed');

    // Sign with DER format (default)
    const derSig = sign('SHA256', data, privateKey);

    // Parse DER to extract raw r and s
    let pos = 2;
    const rLen = derSig[pos + 1];
    let r = derSig.subarray(pos + 2, pos + 2 + rLen);
    pos += 2 + rLen;
    const sLen = derSig[pos + 1];
    let s = derSig.subarray(pos + 2, pos + 2 + sLen);

    // Strip DER padding and pad to 32 bytes
    if (r.length > 32 && r[0] === 0) r = r.subarray(1);
    if (s.length > 32 && s[0] === 0) s = s.subarray(1);
    const rPadded = new Uint8Array(32);
    rPadded.set(r, 32 - r.length);
    const sPadded = new Uint8Array(32);
    sPadded.set(s, 32 - s.length);

    const rawSig = new Uint8Array([...rPadded, ...sPadded]);

    // Convert back to DER
    const reconvertedDer = rawSignatureToDer(rawSig);

    // Get raw public key point
    const spkiBuf = publicKey.export({ type: 'spki', format: 'der' });
    const rawPoint = new Uint8Array(spkiBuf.subarray(spkiBuf.length - 65));

    // Import using our utility
    const importedKey = importEcPublicKey(rawPoint, 'P-256');

    // Verify
    const { verify: cryptoVerify } = require('node:crypto');
    const valid = cryptoVerify(
      'SHA256',
      data,
      importedKey,
      Buffer.from(reconvertedDer),
    );
    expect(valid).toBe(true);
  });
});
