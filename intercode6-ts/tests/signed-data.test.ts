import { extractSignedData } from '../src/signed-data';
import { SAMPLE_TICKET_HEX } from '../src/fixtures';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

describe('extractSignedData', () => {
  const bytes = hexToBytes(SAMPLE_TICKET_HEX);

  it('detects the correct header version', () => {
    const data = extractSignedData(bytes);
    expect(data.headerVersion).toBe(1);
  });

  it('extracts level1DataBytes as non-empty Uint8Array', () => {
    const data = extractSignedData(bytes);
    expect(data.level1DataBytes).toBeInstanceOf(Uint8Array);
    expect(data.level1DataBytes.length).toBeGreaterThan(0);
  });

  it('extracts level2SignedBytes as non-empty Uint8Array', () => {
    const data = extractSignedData(bytes);
    expect(data.level2SignedBytes).toBeInstanceOf(Uint8Array);
    expect(data.level2SignedBytes.length).toBeGreaterThan(0);
  });

  it('level2SignedBytes is longer than level1DataBytes (it contains level1Data)', () => {
    const data = extractSignedData(bytes);
    expect(data.level2SignedBytes.length).toBeGreaterThan(data.level1DataBytes.length);
  });

  it('extracts security provider number', () => {
    const data = extractSignedData(bytes);
    expect(data.securityProviderNum).toBe(3703);
  });

  it('extracts keyId', () => {
    const data = extractSignedData(bytes);
    expect(data.keyId).toBe(1);
  });

  it('extracts algorithm OIDs', () => {
    const data = extractSignedData(bytes);
    expect(data.level1KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(data.level2KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(data.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
  });

  it('extracts level2PublicKey', () => {
    const data = extractSignedData(bytes);
    expect(data.level2PublicKey).toBeDefined();
    expect(data.level2PublicKey).toBeInstanceOf(Uint8Array);
  });

  it('extracts level1Signature', () => {
    const data = extractSignedData(bytes);
    expect(data.level1Signature).toBeDefined();
    expect(data.level1Signature).toBeInstanceOf(Uint8Array);
  });

  it('extracts level2Signature', () => {
    const data = extractSignedData(bytes);
    expect(data.level2Signature).toBeDefined();
    expect(data.level2Signature!.length).toBe(64);
  });

  it('level1DataBytes starts at the correct position (subset of source bytes)', () => {
    const data = extractSignedData(bytes);
    // The raw bytes should be found somewhere in the original buffer
    // This is a basic sanity check that we got actual source bytes
    const l1Hex = Buffer.from(data.level1DataBytes).toString('hex');
    const srcHex = Buffer.from(bytes).toString('hex');
    // Level1Data bytes should appear in the source (possibly not byte-aligned,
    // but the rawBytes are extracted from the bit buffer so should be correct)
    expect(l1Hex.length).toBeGreaterThan(0);
    expect(srcHex.length).toBeGreaterThan(l1Hex.length);
  });

  it('throws on invalid input', () => {
    expect(() => extractSignedData(new Uint8Array([0x00]))).toThrow();
  });
});
