/**
 * End-to-end test: decode a real UIC barcode header from a hex fixture
 * using the pre-compiled v1.0.0 schema from schemas/uic-barcode/.
 *
 * The fixture data is encoded using the v1.0.0 UIC barcode header schema
 * (Level1DataType without validity period fields).
 */
import * as fs from 'fs';
import * as path from 'path';
import { SchemaCodec } from '../../src/schema/SchemaCodec';
import type { SchemaNode } from '../../src/schema/SchemaBuilder';

// Load the pre-compiled v1.0.0 schema
import headerSchemas from '../../schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';

/** Strip whitespace and trailing 'h' suffix from a hex fixture file. */
function loadHexFixture(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf-8');
  return raw.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
}

const FIXTURE_PATH = path.join(__dirname, '..', 'fixtures', 'uicBarcodeHeader_sample1.hex');

describe('UIC Barcode Header fixture decode', () => {
  const hex = loadHexFixture(FIXTURE_PATH);
  let codec: SchemaCodec;

  beforeAll(() => {
    codec = new SchemaCodec(
      headerSchemas.UicBarcodeHeader as unknown as SchemaNode,
    );
  });

  it('decodes the fixture hex with correct top-level structure', () => {
    const decoded = codec.decodeFromHex(hex) as any;

    // Top-level UicBarcodeHeader fields
    expect(decoded.format).toBe('U1');
    expect(decoded.level2SignedData).toBeDefined();
    expect(decoded.level2Signature).toBeInstanceOf(Uint8Array);
    expect(decoded.level2Signature.length).toBe(64);
  });

  it('decodes Level2DataType fields', () => {
    const decoded = codec.decodeFromHex(hex) as any;
    const l2 = decoded.level2SignedData;

    expect(l2.level1Data).toBeDefined();

    // level1Signature: 64-byte ECDSA signature
    expect(l2.level1Signature).toBeInstanceOf(Uint8Array);
    expect(l2.level1Signature.length).toBe(64);

    // level2Data: dynamic content block
    expect(l2.level2Data).toBeDefined();
    expect(l2.level2Data.dataFormat).toBe('_3703.ID1');
    expect(l2.level2Data.data).toBeInstanceOf(Uint8Array);
    expect(l2.level2Data.data.length).toBe(6);
  });

  it('decodes Level1DataType fields', () => {
    const decoded = codec.decodeFromHex(hex) as any;
    const l1 = decoded.level2SignedData.level1Data;

    expect(l1.securityProviderNum).toBe(3703);
    expect(l1.securityProviderIA5).toBeUndefined();
    expect(l1.keyId).toBe(1);

    // dataSequence: single FCB2 data block
    expect(l1.dataSequence).toHaveLength(1);
    expect(l1.dataSequence[0].dataFormat).toBe('FCB2');
    expect(l1.dataSequence[0].data).toBeInstanceOf(Uint8Array);
    expect(l1.dataSequence[0].data.length).toBe(85);

    // OID fields: EC key + ECDSA signing algorithms
    expect(l1.level1KeyAlg).toBe('1.2.840.10045.3.1.7');   // secp256r1
    expect(l1.level2KeyAlg).toBe('1.2.840.10045.3.1.7');    // secp256r1
    expect(l1.level1SigningAlg).toBeUndefined();
    expect(l1.level2SigningAlg).toBe('1.2.840.10045.4.3.2'); // ECDSA-SHA256

    // level2PublicKey: compressed EC point (33 bytes)
    expect(l1.level2PublicKey).toBeInstanceOf(Uint8Array);
    expect(l1.level2PublicKey.length).toBe(33);
  });

  it('round-trips the decoded value', () => {
    const decoded = codec.decodeFromHex(hex);
    const reEncoded = codec.encodeToHex(decoded);
    const reDecoded = codec.decodeFromHex(reEncoded);
    expect(reDecoded).toEqual(decoded);
  });

  it('re-encodes to the original hex', () => {
    const decoded = codec.decodeFromHex(hex);
    const reEncoded = codec.encodeToHex(decoded);
    expect(reEncoded).toBe(hex);
  });
});
