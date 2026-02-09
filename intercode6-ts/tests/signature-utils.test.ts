import {
  rawSignatureToDer,
  importEcPublicKey,
  validateEcSignatureSize,
} from '../src/signature-utils';
import { generateKeyPairSync, sign, verify } from 'node:crypto';

describe('rawSignatureToDer', () => {
  it('converts a 64-byte P-256 raw signature to valid DER', () => {
    // Known r and s values (32 bytes each)
    const r = new Uint8Array(32).fill(0x01);
    const s = new Uint8Array(32).fill(0x02);
    const raw = new Uint8Array([...r, ...s]);

    const der = rawSignatureToDer(raw);

    // DER should start with SEQUENCE tag (0x30)
    expect(der[0]).toBe(0x30);

    // Find the two INTEGERs inside
    let pos = 2; // skip SEQUENCE tag + length
    expect(der[pos]).toBe(0x02); // first INTEGER tag
    const rLen = der[pos + 1];
    pos += 2 + rLen;
    expect(der[pos]).toBe(0x02); // second INTEGER tag
  });

  it('handles leading zeros correctly (strips them)', () => {
    const r = new Uint8Array(32);
    r[0] = 0x00;
    r[1] = 0x00;
    r[2] = 0x42; // first non-zero
    const s = new Uint8Array(32);
    s[0] = 0x01;

    const raw = new Uint8Array([...r, ...s]);
    const der = rawSignatureToDer(raw);

    expect(der[0]).toBe(0x30);
    // r should be trimmed
    expect(der[2]).toBe(0x02); // INTEGER tag
    // The length should be 30 (32 - 2 leading zeros)
    expect(der[3]).toBe(30);
  });

  it('adds padding byte when high bit is set', () => {
    const r = new Uint8Array(32);
    r[0] = 0x80; // high bit set
    const s = new Uint8Array(32);
    s[0] = 0x01;

    const raw = new Uint8Array([...r, ...s]);
    const der = rawSignatureToDer(raw);

    expect(der[2]).toBe(0x02); // INTEGER tag
    expect(der[3]).toBe(33); // 32 bytes + 1 padding byte
    expect(der[4]).toBe(0x00); // padding byte
    expect(der[5]).toBe(0x80); // original first byte
  });

  it('rejects empty input', () => {
    expect(() => rawSignatureToDer(new Uint8Array(0))).toThrow('even and non-zero');
  });

  it('rejects odd-length input', () => {
    expect(() => rawSignatureToDer(new Uint8Array(63))).toThrow('even and non-zero');
  });

  it('produces DER that Node.js crypto accepts for verification', () => {
    // Generate an ECDSA key pair
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });

    const data = Buffer.from('test data for signing');

    // Sign with Node.js to get DER signature, then parse to raw
    const derSig = sign('SHA256', data, privateKey);

    // Parse the DER to extract raw r and s
    // DER: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    let pos = 2;
    const rLen = derSig[pos + 1];
    let r = derSig.subarray(pos + 2, pos + 2 + rLen);
    pos += 2 + rLen;
    const sLen = derSig[pos + 1];
    let s = derSig.subarray(pos + 2, pos + 2 + sLen);

    // Strip leading padding
    if (r.length > 32 && r[0] === 0) r = r.subarray(1);
    if (s.length > 32 && s[0] === 0) s = s.subarray(1);

    // Pad to 32 bytes
    const rPadded = new Uint8Array(32);
    rPadded.set(r, 32 - r.length);
    const sPadded = new Uint8Array(32);
    sPadded.set(s, 32 - s.length);

    const rawSig = new Uint8Array([...rPadded, ...sPadded]);

    // Convert back to DER using our function
    const reconverted = rawSignatureToDer(rawSig);

    // Verify with Node.js crypto using the reconverted DER
    const valid = verify('SHA256', data, publicKey, Buffer.from(reconverted));
    expect(valid).toBe(true);
  });
});

describe('importEcPublicKey', () => {
  it('imports an uncompressed P-256 public key', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    // Export the key as uncompressed point
    const rawBuf = publicKey.export({ type: 'spki', format: 'der' });
    // Extract the raw point from SPKI DER (last 65 bytes for P-256 uncompressed)
    const rawPoint = new Uint8Array(rawBuf.subarray(rawBuf.length - 65));

    expect(rawPoint[0]).toBe(0x04); // uncompressed prefix

    const imported = importEcPublicKey(rawPoint, 'P-256');
    expect(imported.asymmetricKeyType).toBe('ec');
  });

  it('throws for unsupported curve', () => {
    const rawPoint = new Uint8Array(65);
    rawPoint[0] = 0x04;
    expect(() => importEcPublicKey(rawPoint, 'P-999')).toThrow('Unsupported EC curve');
  });

  it('round-trips sign/verify with imported key', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });

    // Get raw point
    const rawBuf = publicKey.export({ type: 'spki', format: 'der' });
    const rawPoint = new Uint8Array(rawBuf.subarray(rawBuf.length - 65));

    // Import the raw point
    const imported = importEcPublicKey(rawPoint, 'P-256');

    // Sign some data
    const data = Buffer.from('hello world');
    const signature = sign('SHA256', data, privateKey);

    // Verify with the imported key
    const valid = verify('SHA256', data, imported, signature);
    expect(valid).toBe(true);
  });
});

describe('validateEcSignatureSize', () => {
  it('accepts 64 bytes for P-256', () => {
    expect(validateEcSignatureSize(new Uint8Array(64), 'P-256')).toBeUndefined();
  });

  it('accepts 96 bytes for P-384', () => {
    expect(validateEcSignatureSize(new Uint8Array(96), 'P-384')).toBeUndefined();
  });

  it('accepts 132 bytes for P-521', () => {
    expect(validateEcSignatureSize(new Uint8Array(132), 'P-521')).toBeUndefined();
  });

  it('rejects wrong size for P-256', () => {
    const err = validateEcSignatureSize(new Uint8Array(48), 'P-256');
    expect(err).toContain('Expected 64');
    expect(err).toContain('got 48');
  });

  it('returns undefined for unknown curve', () => {
    expect(validateEcSignatureSize(new Uint8Array(64), 'P-999')).toBeUndefined();
  });
});
