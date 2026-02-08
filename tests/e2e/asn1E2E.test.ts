/**
 * End-to-end tests: ASN.1 text -> parser -> schema -> codec -> PER encode/decode.
 *
 * Tests the full pipeline using real-world ASN.1 type definitions from
 * the Intercode specification (NF EN 12320) and UIC barcode header standard.
 * Expected PER unaligned encoding hex values are taken directly from the
 * specification documents.
 *
 * Every test is a round-trip test: encode a value, decode the result, and
 * verify it equals the original. The two "known hex" tests additionally
 * verify the encoded output matches the specification hex.
 */
import * as fs from 'fs';
import * as path from 'path';
import { parseAsn1Module } from '../../src/parser/AsnParser';
import { convertModuleToSchemaNodes } from '../../src/parser/toSchemaNode';
import { SchemaCodec } from '../../src/schema/SchemaCodec';
import type { SchemaNode } from '../../src/schema/SchemaBuilder';

/**
 * ASN.1 module combining the Intercode-specific types:
 * - RetailChannelData (ENUMERATED with extension marker)
 * - ProductRetailerData (SEQUENCE with all-OPTIONAL fields and extension marker)
 * - IntercodeIssuingData (SEQUENCE with type references, OCTET STRING SIZE, extension marker)
 * - IntercodeDynamicData (SEQUENCE with DEFAULT, negative ranges, extension marker)
 */
const INTERCODE_MODULE = `
Intercode DEFINITIONS ::= BEGIN

  RetailChannelData ::= ENUMERATED {
    smsTicket (0),
    mobileApplication (1),
    webSite (2),
    ticketOffice (3),
    depositaryTerminal (4),
    onBoardTerminal (5),
    ticketVendingMachine (6),
    ...
  }

  ProductRetailerData ::= SEQUENCE {
    retailChannel RetailChannelData OPTIONAL,
    retailGeneratorId INTEGER (0..255) OPTIONAL,
    retailServerId INTEGER (0..255) OPTIONAL,
    retailerId INTEGER (0..4095) OPTIONAL,
    retailPointId INTEGER OPTIONAL,
    ...
  }

  IntercodeIssuingData ::= SEQUENCE {
    intercodeVersion INTEGER (0..7),
    intercodeInstanciation INTEGER (0..7),
    networkId OCTET STRING (SIZE (3)),
    productRetailer ProductRetailerData OPTIONAL,
    ...
  }

  IntercodeDynamicData ::= SEQUENCE {
    dynamicContentDay INTEGER (-1..1070) DEFAULT 0,
    dynamicContentTime INTEGER (0..86399) OPTIONAL,
    dynamicContentUTCOffset INTEGER (-60..60) OPTIONAL,
    dynamicContentDuration INTEGER (0..86399) OPTIONAL,
    ...
  }

END
`;

describe('End-to-end: ASN.1 parse -> schema -> PER encode/decode', () => {

  // ---------------------------------------------------------------------------
  // IntercodeIssuingData (Intercode specification F.3.1)
  // ---------------------------------------------------------------------------
  describe('IntercodeIssuingData (Intercode spec F.3.1)', () => {
    let codec: SchemaCodec;

    const VALUE = {
      intercodeVersion: 1,
      intercodeInstanciation: 1,
      networkId: new Uint8Array([0x25, 0x09, 0x15]),
      productRetailer: {
        retailChannel: 'mobileApplication',
        retailGeneratorId: 0,
        retailServerId: 32,
        retailerId: 1037,
        retailPointId: 6,
      },
    };

    // Expected hex from Intercode specification F.3.1 (11 bytes)
    const EXPECTED_HEX = '492509157c400810340418';

    beforeAll(() => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      const schemas = convertModuleToSchemaNodes(module);
      codec = new SchemaCodec(schemas['IntercodeIssuingData']);
    });

    it('round-trips spec value and matches expected hex', () => {
      const hex = codec.encodeToHex(VALUE);
      expect(hex).toBe(EXPECTED_HEX);
      expect(hex.length / 2).toBe(11);
      expect(codec.decodeFromHex(hex)).toEqual(VALUE);
    });

    it('round-trips without optional productRetailer', () => {
      const value = {
        intercodeVersion: 1,
        intercodeInstanciation: 1,
        networkId: new Uint8Array([0x25, 0x09, 0x15]),
      };
      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded).toEqual(value);
      expect(decoded.productRetailer).toBeUndefined();
    });

    it('produces smaller encoding when optional fields are absent', () => {
      const hexFull = codec.encodeToHex(VALUE);
      const valueNoRetailer = {
        intercodeVersion: 1,
        intercodeInstanciation: 1,
        networkId: new Uint8Array([0x25, 0x09, 0x15]),
      };
      const hexNoRetailer = codec.encodeToHex(valueNoRetailer);
      expect(hexNoRetailer.length).toBeLessThan(hexFull.length);
      // Both still round-trip
      expect(codec.decodeFromHex(hexFull)).toEqual(VALUE);
      expect(codec.decodeFromHex(hexNoRetailer)).toEqual(valueNoRetailer);
    });

    it('round-trips with partial ProductRetailerData (some optional fields)', () => {
      const value = {
        intercodeVersion: 2,
        intercodeInstanciation: 0,
        networkId: new Uint8Array([0x00, 0x00, 0x01]),
        productRetailer: {
          retailChannel: 'webSite',
          retailerId: 100,
        },
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips all RetailChannelData enum values', () => {
      const channels = [
        'smsTicket', 'mobileApplication', 'webSite', 'ticketOffice',
        'depositaryTerminal', 'onBoardTerminal', 'ticketVendingMachine',
      ];
      for (const channel of channels) {
        const value = {
          intercodeVersion: 0,
          intercodeInstanciation: 0,
          networkId: new Uint8Array([0x00, 0x00, 0x00]),
          productRetailer: { retailChannel: channel },
        };
        expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
      }
    });

    it('round-trips constraint boundary values', () => {
      const value = {
        intercodeVersion: 7,
        intercodeInstanciation: 7,
        networkId: new Uint8Array([0xFF, 0xFF, 0xFF]),
        productRetailer: {
          retailGeneratorId: 255,
          retailServerId: 255,
          retailerId: 4095,
        },
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });
  });

  // ---------------------------------------------------------------------------
  // IntercodeDynamicData (Intercode specification F.4)
  // ---------------------------------------------------------------------------
  describe('IntercodeDynamicData (Intercode spec F.4)', () => {
    let codec: SchemaCodec;

    const VALUE = {
      dynamicContentDay: 0,
      dynamicContentTime: 59710,
      dynamicContentUTCOffset: -8,
      dynamicContentDuration: 600,
    };

    // Expected hex from Intercode specification F.4 (6 bytes)
    const EXPECTED_HEX = '3ba4f9a00960';

    beforeAll(() => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      const schemas = convertModuleToSchemaNodes(module);
      codec = new SchemaCodec(schemas['IntercodeDynamicData']);
    });

    it('round-trips spec value and matches expected hex', () => {
      const hex = codec.encodeToHex(VALUE);
      expect(hex).toBe(EXPECTED_HEX);
      expect(hex.length / 2).toBe(6);
      expect(codec.decodeFromHex(hex)).toEqual(VALUE);
    });

    it('round-trips DEFAULT value (dynamicContentDay=0) with optional fields', () => {
      const valueWithDefault = { dynamicContentDay: 0, dynamicContentTime: 100 };
      expect(codec.decodeFromHex(codec.encodeToHex(valueWithDefault))).toEqual(valueWithDefault);

      const valueWithNonDefault = { dynamicContentDay: 5, dynamicContentTime: 100 };
      expect(codec.decodeFromHex(codec.encodeToHex(valueWithNonDefault))).toEqual(valueWithNonDefault);

      // Non-default value requires at least as many bits
      expect(codec.encodeToHex(valueWithNonDefault).length).toBeGreaterThanOrEqual(
        codec.encodeToHex(valueWithDefault).length,
      );
    });

    it('round-trips negative constraint values (dynamicContentDay=-1)', () => {
      const value = { dynamicContentDay: -1, dynamicContentTime: 0 };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips negative UTC offset', () => {
      const value = { dynamicContentDay: 0, dynamicContentUTCOffset: -60 };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips positive UTC offset', () => {
      const value = { dynamicContentDay: 0, dynamicContentUTCOffset: 60 };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips constraint boundary max values', () => {
      const value = {
        dynamicContentDay: 1070,
        dynamicContentTime: 86399,
        dynamicContentUTCOffset: 60,
        dynamicContentDuration: 86399,
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips constraint boundary min values', () => {
      const value = {
        dynamicContentDay: -1,
        dynamicContentTime: 0,
        dynamicContentUTCOffset: -60,
        dynamicContentDuration: 0,
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips minimal data (all optional absent, default used)', () => {
      const value = { dynamicContentDay: 0 };
      const decoded = codec.decodeFromHex(codec.encodeToHex(value)) as Record<string, unknown>;
      expect(decoded.dynamicContentDay).toBe(0);
      expect(decoded.dynamicContentTime).toBeUndefined();
      expect(decoded.dynamicContentUTCOffset).toBeUndefined();
      expect(decoded.dynamicContentDuration).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // UIC Barcode Header (using existing .asn fixture, with native OID support)
  // ---------------------------------------------------------------------------
  describe('UIC Barcode Header (fixture, native OID)', () => {
    const FIXTURE_PATH = path.join(__dirname, '..', 'fixtures', 'uicBarcodeHeader_v2.0.1.asn');
    const asnText = fs.readFileSync(FIXTURE_PATH, 'utf-8');

    let schemas: Record<string, SchemaNode>;

    beforeAll(() => {
      const module = parseAsn1Module(asnText);
      schemas = convertModuleToSchemaNodes(module);
    });

    it('builds codecs for all 4 types', () => {
      expect(Object.keys(schemas)).toHaveLength(4);
      for (const typeName of Object.keys(schemas)) {
        const codec = new SchemaCodec(schemas[typeName]);
        expect(codec).toBeDefined();
      }
    });

    it('round-trips DataType with realistic values', () => {
      const codec = new SchemaCodec(schemas['DataType']);
      const value = {
        dataFormat: 'FCB2',
        data: new Uint8Array([0x22, 0x21, 0x01, 0xCE]),
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips Level1DataType with OID fields', () => {
      const codec = new SchemaCodec(schemas['Level1DataType']);

      const ticketData = new Uint8Array([
        0x22, 0x21, 0x01, 0xCE, 0xC0, 0x87, 0x87, 0xC6,
        0x42, 0x2F, 0xB3, 0x6E, 0xC1, 0x9C, 0x99, 0x2C,
      ]);
      const publicKey = new Uint8Array([
        0x03, 0x54, 0x64, 0x5D, 0x7E, 0x8E, 0x43, 0x81,
        0x3C, 0x4C, 0x32, 0x9C, 0xED, 0x33, 0xE8, 0x64,
        0x60, 0x52, 0x32, 0x14, 0x87, 0x41, 0x85, 0x77,
        0x59, 0x17, 0xF4, 0x3C, 0x62, 0x92, 0x77, 0x96, 0xE7,
      ]);

      const value = {
        securityProviderNum: 3703,
        keyId: 1,
        dataSequence: [
          { dataFormat: 'FCB2', data: ticketData },
        ],
        level1KeyAlg: '1.2.840.113549.1.1.1',
        level2KeyAlg: '1.2.840.10045.2.1',
        level1SigningAlg: '1.2.840.113549.1.1.11',
        level2SigningAlg: '1.2.840.10045.4.3.2',
        level2PublicKey: publicKey,
      };

      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips Level1DataType without optional OID fields', () => {
      const codec = new SchemaCodec(schemas['Level1DataType']);

      const value = {
        securityProviderNum: 3703,
        keyId: 1,
        dataSequence: [
          { dataFormat: 'FCB2', data: new Uint8Array([0x01]) },
        ],
        level2PublicKey: new Uint8Array([0x03, 0x54]),
      };

      const decoded = codec.decodeFromHex(codec.encodeToHex(value)) as Record<string, unknown>;
      expect(decoded).toEqual(value);
      expect(decoded.level1KeyAlg).toBeUndefined();
      expect(decoded.level2KeyAlg).toBeUndefined();
      expect(decoded.level1SigningAlg).toBeUndefined();
      expect(decoded.level2SigningAlg).toBeUndefined();
    });

    it('round-trips Level2DataType with signature and dynamic data', () => {
      const codec = new SchemaCodec(schemas['Level2DataType']);

      const fakeSig = new Uint8Array(Array(64).fill(0x11));
      const dynamicData = new Uint8Array([0x3B, 0xA4, 0xF9, 0xA0, 0x09, 0x60]);

      const value = {
        level1Data: {
          securityProviderNum: 3703,
          keyId: 1,
          dataSequence: [
            { dataFormat: 'FCB2', data: new Uint8Array([0x01]) },
          ],
        },
        level1Signature: fakeSig,
        level2Data: {
          dataFormat: '_3703.ID1',
          data: dynamicData,
        },
      };

      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips full UicBarcodeHeader with all nested data', () => {
      const codec = new SchemaCodec(schemas['UicBarcodeHeader']);

      const staticSig = new Uint8Array(Array(64).fill(0x11));
      const dynamicSig = new Uint8Array(Array(64).fill(0x22));

      const value = {
        format: 'U1',
        level2SignedData: {
          level1Data: {
            securityProviderNum: 3703,
            keyId: 1,
            dataSequence: [
              {
                dataFormat: 'FCB2',
                data: new Uint8Array([0xAA, 0xBB, 0xCC]),
              },
            ],
            level1KeyAlg: '2.16.840.1.101.3.4.2.1',
            level2PublicKey: new Uint8Array([0x03, 0x54]),
          },
          level1Signature: staticSig,
          level2Data: {
            dataFormat: '_3703.ID1',
            data: new Uint8Array([0x3B, 0xA4, 0xF9, 0xA0, 0x09, 0x60]),
          },
        },
        level2Signature: dynamicSig,
      };

      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips UicBarcodeHeader without optional fields', () => {
      const codec = new SchemaCodec(schemas['UicBarcodeHeader']);

      const value = {
        format: 'U1',
        level2SignedData: {
          level1Data: {
            dataSequence: [
              { dataFormat: 'TEST', data: new Uint8Array([0x00]) },
            ],
          },
        },
      };

      const decoded = codec.decodeFromHex(codec.encodeToHex(value)) as Record<string, unknown>;
      expect(decoded).toEqual(value);
      expect(decoded.level2Signature).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Cross-type encoding: both Intercode types from the same module
  // ---------------------------------------------------------------------------
  describe('Combined Intercode module cross-type tests', () => {
    let schemas: Record<string, SchemaNode>;

    beforeAll(() => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      schemas = convertModuleToSchemaNodes(module);
    });

    it('round-trips both Intercode types matching spec hex', () => {
      const issuingCodec = new SchemaCodec(schemas['IntercodeIssuingData']);
      const dynamicCodec = new SchemaCodec(schemas['IntercodeDynamicData']);

      const issuingValue = {
        intercodeVersion: 1,
        intercodeInstanciation: 1,
        networkId: new Uint8Array([0x25, 0x09, 0x15]),
        productRetailer: {
          retailChannel: 'mobileApplication',
          retailGeneratorId: 0,
          retailServerId: 32,
          retailerId: 1037,
          retailPointId: 6,
        },
      };
      const issuingHex = issuingCodec.encodeToHex(issuingValue);
      expect(issuingHex).toBe('492509157c400810340418');
      expect(issuingCodec.decodeFromHex(issuingHex)).toEqual(issuingValue);

      const dynamicValue = {
        dynamicContentDay: 0,
        dynamicContentTime: 59710,
        dynamicContentUTCOffset: -8,
        dynamicContentDuration: 600,
      };
      const dynamicHex = dynamicCodec.encodeToHex(dynamicValue);
      expect(dynamicHex).toBe('3ba4f9a00960');
      expect(dynamicCodec.decodeFromHex(dynamicHex)).toEqual(dynamicValue);
    });

    it('round-trips RetailChannelData as standalone extensible enum', () => {
      const codec = new SchemaCodec(schemas['RetailChannelData']);

      const allValues = [
        'smsTicket', 'mobileApplication', 'webSite', 'ticketOffice',
        'depositaryTerminal', 'onBoardTerminal', 'ticketVendingMachine',
      ];
      for (const val of allValues) {
        expect(codec.decodeFromHex(codec.encodeToHex(val))).toBe(val);
      }
    });

    it('round-trips ProductRetailerData as standalone type', () => {
      const codec = new SchemaCodec(schemas['ProductRetailerData']);

      const value = {
        retailChannel: 'ticketVendingMachine',
        retailGeneratorId: 255,
        retailServerId: 128,
        retailerId: 2000,
        retailPointId: 100,
      };
      expect(codec.decodeFromHex(codec.encodeToHex(value))).toEqual(value);
    });

    it('round-trips dynamic data encoded as standalone bytes', () => {
      const dynamicCodec = new SchemaCodec(schemas['IntercodeDynamicData']);

      const dynamicValue = {
        dynamicContentDay: 0,
        dynamicContentTime: 59710,
        dynamicContentUTCOffset: -8,
        dynamicContentDuration: 600,
      };

      // Encode and verify raw bytes match spec
      const dynamicBytes = dynamicCodec.encode(dynamicValue);
      expect(dynamicBytes).toEqual(new Uint8Array([0x3B, 0xA4, 0xF9, 0xA0, 0x09, 0x60]));

      // Round-trip from bytes
      expect(dynamicCodec.decode(dynamicBytes)).toEqual(dynamicValue);
    });
  });
});
