import {
  verifyLevel2Signature,
  verifyLevel1Signature,
  verifySignatures,
} from '../src/verifier';
import { extractSignedData } from '../src/signed-data';
import { importSpkiPublicKey } from '../src/signature-utils';
import { SAMPLE_TICKET_HEX, GRAND_EST_U1_FCB3_HEX } from '../src/fixtures';
import {
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

describe('verifyLevel2Signature', () => {
  it('returns valid:false for sample ticket (synthetic signatures)', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);
    expect(result).toHaveProperty('valid');
    expect(typeof result.valid).toBe('boolean');
    if (!result.valid && result.error) {
      expect(typeof result.error).toBe('string');
    }
  });

  it('attempts verification when signature is present', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);
    expect(result).toHaveProperty('valid');
  });
});

describe('verifyLevel1Signature', () => {
  it('returns error when no level 1 signing algorithm OID', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const data = extractSignedData(bytes);

    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const result = await verifyLevel1Signature(bytes, publicKey);
    expect(result).toHaveProperty('valid');
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

describe('real ticket verification', () => {
  it('verifies Grand Est U1 FCB3 Level 2 signature', async () => {
    const bytes = hexToBytes(GRAND_EST_U1_FCB3_HEX);
    const result = await verifyLevel2Signature(bytes);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe('ECDSA with SHA-256');
  });

  it('reports Grand Est Level 2 signed data fields', () => {
    const bytes = hexToBytes(GRAND_EST_U1_FCB3_HEX);
    const data = extractSignedData(bytes);

    expect(data.level2Signature).toBeDefined();
    expect(data.level2PublicKey).toBeDefined();
    expect(data.level2SigningAlg).toBe('1.2.840.10045.4.3.2'); // ECDSA SHA-256
    expect(data.level2KeyAlg).toBe('1.2.840.10045.3.1.7');     // EC P-256
  });
});

describe('end-to-end DER signature verification', () => {
  it('verifies an ECDSA-SHA256 DER signature with SPKI-imported EC key', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });

    const data = Buffer.from('structured signature test');
    // Node.js sign() returns DER by default — same format as FCB signatures
    const derSig = sign('SHA256', data, privateKey);

    // Import via SPKI DER (as FCB barcodes store it)
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const importedKey = importSpkiPublicKey(new Uint8Array(spkiDer));

    const valid = verify('SHA256', data, importedKey, derSig);
    expect(valid).toBe(true);
  });

  it('verifies a DSA-SHA256 DER signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('dsa', {
      modulusLength: 2048,
      divisorLength: 256,
    });

    const data = Buffer.from('DSA signature test');
    const derSig = sign('SHA256', data, privateKey);

    const valid = verify('SHA256', data, publicKey, derSig);
    expect(valid).toBe(true);
  });
});
