/**
 * End-to-end tests: ASN.1 text -> parser -> schema -> codec -> PER encode/decode.
 *
 * Tests the full pipeline using real-world ASN.1 type definitions from
 * the Intercode specification (NF EN 12320) and UIC barcode header standard.
 * Expected PER unaligned encoding hex values are taken directly from the
 * specification documents.
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

    it('parses the ASN.1 module with 4 type assignments', () => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      expect(module.assignments).toHaveLength(4);
      expect(module.assignments.map(a => a.name)).toEqual([
        'RetailChannelData',
        'ProductRetailerData',
        'IntercodeIssuingData',
        'IntercodeDynamicData',
      ]);
    });

    it('converts all types to schema nodes with correct structure', () => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      const schemas = convertModuleToSchemaNodes(module);
      expect(Object.keys(schemas)).toHaveLength(4);

      // IntercodeIssuingData should resolve ProductRetailerData inline
      const issuing = schemas['IntercodeIssuingData'] as {
        type: string;
        fields: Array<{ name: string; schema: { type: string }; optional?: boolean }>;
        extensionFields?: unknown[];
      };
      expect(issuing.type).toBe('SEQUENCE');
      expect(issuing.fields).toHaveLength(4);
      expect(issuing.fields[3].name).toBe('productRetailer');
      expect(issuing.fields[3].optional).toBe(true);
      expect(issuing.fields[3].schema.type).toBe('SEQUENCE'); // resolved from ProductRetailerData
      expect(issuing.extensionFields).toEqual([]);
    });

    it('encodes to expected hex (11 bytes)', () => {
      const hex = codec.encodeToHex(VALUE);
      expect(hex).toBe(EXPECTED_HEX);
      expect(hex.length / 2).toBe(11);
    });

    it('decodes from expected hex back to original value', () => {
      const decoded = codec.decodeFromHex(EXPECTED_HEX) as Record<string, unknown>;
      expect(decoded.intercodeVersion).toBe(1);
      expect(decoded.intercodeInstanciation).toBe(1);
      expect(decoded.networkId).toEqual(new Uint8Array([0x25, 0x09, 0x15]));

      const retailer = decoded.productRetailer as Record<string, unknown>;
      expect(retailer.retailChannel).toBe('mobileApplication');
      expect(retailer.retailGeneratorId).toBe(0);
      expect(retailer.retailServerId).toBe(32);
      expect(retailer.retailerId).toBe(1037);
      expect(retailer.retailPointId).toBe(6);
    });

    it('round-trips encode -> decode', () => {
      const hex = codec.encodeToHex(VALUE);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.intercodeVersion).toBe(VALUE.intercodeVersion);
      expect(decoded.intercodeInstanciation).toBe(VALUE.intercodeInstanciation);
      expect(decoded.networkId).toEqual(VALUE.networkId);
      expect(decoded.productRetailer).toEqual(VALUE.productRetailer);
    });

    it('encodes without optional productRetailer', () => {
      const valueNoRetailer = {
        intercodeVersion: 1,
        intercodeInstanciation: 1,
        networkId: new Uint8Array([0x25, 0x09, 0x15]),
      };
      const hex = codec.encodeToHex(valueNoRetailer);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.intercodeVersion).toBe(1);
      expect(decoded.intercodeInstanciation).toBe(1);
      expect(decoded.networkId).toEqual(new Uint8Array([0x25, 0x09, 0x15]));
      expect(decoded.productRetailer).toBeUndefined();
    });

    it('produces smaller encoding when optional fields are absent', () => {
      const hexFull = codec.encodeToHex(VALUE);
      const hexNoRetailer = codec.encodeToHex({
        intercodeVersion: 1,
        intercodeInstanciation: 1,
        networkId: new Uint8Array([0x25, 0x09, 0x15]),
      });
      expect(hexNoRetailer.length).toBeLessThan(hexFull.length);
    });

    it('encodes with partial ProductRetailerData (some optional fields)', () => {
      const valuePartial = {
        intercodeVersion: 2,
        intercodeInstanciation: 0,
        networkId: new Uint8Array([0x00, 0x00, 0x01]),
        productRetailer: {
          retailChannel: 'webSite',
          retailerId: 100,
        },
      };
      const hex = codec.encodeToHex(valuePartial);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.intercodeVersion).toBe(2);
      expect(decoded.intercodeInstanciation).toBe(0);
      expect(decoded.networkId).toEqual(new Uint8Array([0x00, 0x00, 0x01]));

      const retailer = decoded.productRetailer as Record<string, unknown>;
      expect(retailer.retailChannel).toBe('webSite');
      expect(retailer.retailGeneratorId).toBeUndefined();
      expect(retailer.retailServerId).toBeUndefined();
      expect(retailer.retailerId).toBe(100);
      expect(retailer.retailPointId).toBeUndefined();
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
        const hex = codec.encodeToHex(value);
        const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
        const retailer = decoded.productRetailer as Record<string, unknown>;
        expect(retailer.retailChannel).toBe(channel);
      }
    });

    it('handles constraint boundary values', () => {
      const valueBounds = {
        intercodeVersion: 7,       // max
        intercodeInstanciation: 7, // max
        networkId: new Uint8Array([0xFF, 0xFF, 0xFF]),
        productRetailer: {
          retailGeneratorId: 255,  // max
          retailServerId: 255,     // max
          retailerId: 4095,        // max
        },
      };
      const hex = codec.encodeToHex(valueBounds);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.intercodeVersion).toBe(7);
      expect(decoded.intercodeInstanciation).toBe(7);
      expect(decoded.networkId).toEqual(new Uint8Array([0xFF, 0xFF, 0xFF]));

      const retailer = decoded.productRetailer as Record<string, unknown>;
      expect(retailer.retailGeneratorId).toBe(255);
      expect(retailer.retailServerId).toBe(255);
      expect(retailer.retailerId).toBe(4095);
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

    it('converts to schema node with DEFAULT and OPTIONAL fields', () => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      const schemas = convertModuleToSchemaNodes(module);
      const dynamic = schemas['IntercodeDynamicData'] as {
        type: string;
        fields: Array<{ name: string; optional?: boolean; defaultValue?: unknown }>;
        extensionFields?: unknown[];
      };
      expect(dynamic.type).toBe('SEQUENCE');
      expect(dynamic.fields).toHaveLength(4);
      expect(dynamic.fields[0].defaultValue).toBe(0);
      expect(dynamic.fields[1].optional).toBe(true);
      expect(dynamic.fields[2].optional).toBe(true);
      expect(dynamic.fields[3].optional).toBe(true);
      expect(dynamic.extensionFields).toEqual([]);
    });

    it('encodes to expected hex (6 bytes)', () => {
      const hex = codec.encodeToHex(VALUE);
      expect(hex).toBe(EXPECTED_HEX);
      expect(hex.length / 2).toBe(6);
    });

    it('decodes from expected hex back to original value', () => {
      const decoded = codec.decodeFromHex(EXPECTED_HEX);
      expect(decoded).toEqual(VALUE);
    });

    it('round-trips encode -> decode', () => {
      const hex = codec.encodeToHex(VALUE);
      expect(codec.decodeFromHex(hex)).toEqual(VALUE);
    });

    it('DEFAULT value (dynamicContentDay=0) is omitted from encoding', () => {
      const valueWithDefault = { dynamicContentDay: 0, dynamicContentTime: 100 };
      const valueWithNonDefault = { dynamicContentDay: 5, dynamicContentTime: 100 };

      const hexDefault = codec.encodeToHex(valueWithDefault);
      const hexNonDefault = codec.encodeToHex(valueWithNonDefault);

      // Non-default value requires more bits
      expect(hexNonDefault.length).toBeGreaterThanOrEqual(hexDefault.length);

      expect(codec.decodeFromHex(hexDefault)).toEqual(valueWithDefault);
      expect(codec.decodeFromHex(hexNonDefault)).toEqual(valueWithNonDefault);
    });

    it('handles negative constraint values (dynamicContentDay=-1)', () => {
      const valueNeg = { dynamicContentDay: -1, dynamicContentTime: 0 };
      const hex = codec.encodeToHex(valueNeg);
      expect(codec.decodeFromHex(hex)).toEqual(valueNeg);
    });

    it('handles negative UTC offset', () => {
      const valueNegOffset = {
        dynamicContentDay: 0,
        dynamicContentUTCOffset: -60,
      };
      const hex = codec.encodeToHex(valueNegOffset);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.dynamicContentDay).toBe(0);
      expect(decoded.dynamicContentUTCOffset).toBe(-60);
    });

    it('handles positive UTC offset', () => {
      const valuePosOffset = {
        dynamicContentDay: 0,
        dynamicContentUTCOffset: 60,
      };
      const hex = codec.encodeToHex(valuePosOffset);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.dynamicContentUTCOffset).toBe(60);
    });

    it('handles constraint boundary values', () => {
      const valueMax = {
        dynamicContentDay: 1070,
        dynamicContentTime: 86399,
        dynamicContentUTCOffset: 60,
        dynamicContentDuration: 86399,
      };
      const hex = codec.encodeToHex(valueMax);
      expect(codec.decodeFromHex(hex)).toEqual(valueMax);

      const valueMin = {
        dynamicContentDay: -1,
        dynamicContentTime: 0,
        dynamicContentUTCOffset: -60,
        dynamicContentDuration: 0,
      };
      const hexMin = codec.encodeToHex(valueMin);
      expect(codec.decodeFromHex(hexMin)).toEqual(valueMin);
    });

    it('encodes with minimal data (all optional absent, default used)', () => {
      const valueMinimal = { dynamicContentDay: 0 };
      const hex = codec.encodeToHex(valueMinimal);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.dynamicContentDay).toBe(0);
      expect(decoded.dynamicContentTime).toBeUndefined();
      expect(decoded.dynamicContentUTCOffset).toBeUndefined();
      expect(decoded.dynamicContentDuration).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // UIC Barcode Header (using existing .asn fixture, OID fields omitted)
  // ---------------------------------------------------------------------------
  describe('UIC Barcode Header (fixture, OID fields omitted)', () => {
    const FIXTURE_PATH = path.join(__dirname, '..', 'fixtures', 'uicBarcodeHeader_v2.0.1.asn');
    const asnText = fs.readFileSync(FIXTURE_PATH, 'utf-8');

    let schemas: Record<string, unknown>;

    beforeAll(() => {
      const module = parseAsn1Module(asnText);
      schemas = convertModuleToSchemaNodes(module, {
        objectIdentifierHandling: 'omit',
      });
    });

    it('builds codecs for all 4 types', () => {
      expect(Object.keys(schemas)).toHaveLength(4);
      for (const typeName of Object.keys(schemas)) {
        const codec = new SchemaCodec(schemas[typeName] as SchemaNode);
        expect(codec).toBeDefined();
      }
    });

    it('round-trips DataType with realistic values', () => {
      const codec = new SchemaCodec(schemas['DataType'] as SchemaNode);
      const value = {
        dataFormat: 'FCB2',
        data: new Uint8Array([0x22, 0x21, 0x01, 0xCE]),
      };
      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.dataFormat).toBe('FCB2');
      expect(decoded.data).toEqual(new Uint8Array([0x22, 0x21, 0x01, 0xCE]));
    });

    it('round-trips Level1DataType with realistic values (OID fields omitted)', () => {
      const codec = new SchemaCodec(schemas['Level1DataType'] as SchemaNode);

      // Mimic the spec example (F.5.1) but without OID fields
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
        level2PublicKey: publicKey,
      };

      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.securityProviderNum).toBe(3703);
      expect(decoded.keyId).toBe(1);

      const dataSeq = decoded.dataSequence as Array<Record<string, unknown>>;
      expect(dataSeq).toHaveLength(1);
      expect(dataSeq[0].dataFormat).toBe('FCB2');
      expect(dataSeq[0].data).toEqual(ticketData);
      expect(decoded.level2PublicKey).toEqual(publicKey);
    });

    it('round-trips Level2DataType with signature and dynamic data', () => {
      const codec = new SchemaCodec(schemas['Level2DataType'] as SchemaNode);

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

      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;

      const l1 = decoded.level1Data as Record<string, unknown>;
      expect(l1.securityProviderNum).toBe(3703);
      expect(l1.keyId).toBe(1);
      expect(decoded.level1Signature).toEqual(fakeSig);

      const l2Data = decoded.level2Data as Record<string, unknown>;
      expect(l2Data.dataFormat).toBe('_3703.ID1');
      expect(l2Data.data).toEqual(dynamicData);
    });

    it('round-trips full UicBarcodeHeader with all nested data', () => {
      const codec = new SchemaCodec(schemas['UicBarcodeHeader'] as SchemaNode);

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

      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;

      expect(decoded.format).toBe('U1');
      expect(decoded.level2Signature).toEqual(dynamicSig);

      const signed = decoded.level2SignedData as Record<string, unknown>;
      expect(signed.level1Signature).toEqual(staticSig);

      const l1 = signed.level1Data as Record<string, unknown>;
      expect(l1.securityProviderNum).toBe(3703);
      expect(l1.keyId).toBe(1);

      const l2Data = signed.level2Data as Record<string, unknown>;
      expect(l2Data.dataFormat).toBe('_3703.ID1');
    });

    it('handles UicBarcodeHeader without optional fields', () => {
      const codec = new SchemaCodec(schemas['UicBarcodeHeader'] as SchemaNode);

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

      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex) as Record<string, unknown>;
      expect(decoded.format).toBe('U1');
      expect(decoded.level2Signature).toBeUndefined();

      const signed = decoded.level2SignedData as Record<string, unknown>;
      expect(signed.level1Signature).toBeUndefined();
      expect(signed.level2Data).toBeUndefined();

      const l1 = signed.level1Data as Record<string, unknown>;
      expect(l1.securityProviderNum).toBeUndefined();
      expect(l1.keyId).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Cross-type encoding: both Intercode types from the same module
  // ---------------------------------------------------------------------------
  describe('Combined Intercode module cross-type tests', () => {
    let schemas: Record<string, unknown>;

    beforeAll(() => {
      const module = parseAsn1Module(INTERCODE_MODULE);
      schemas = convertModuleToSchemaNodes(module);
    });

    it('builds codecs for all 4 types in the module', () => {
      for (const typeName of Object.keys(schemas)) {
        const codec = new SchemaCodec(schemas[typeName] as SchemaNode);
        expect(codec).toBeDefined();
      }
    });

    it('encodes both IntercodeIssuingData and IntercodeDynamicData matching spec hex', () => {
      const issuingCodec = new SchemaCodec(schemas['IntercodeIssuingData'] as SchemaNode);
      const dynamicCodec = new SchemaCodec(schemas['IntercodeDynamicData'] as SchemaNode);

      const issuingHex = issuingCodec.encodeToHex({
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
      });
      expect(issuingHex).toBe('492509157c400810340418');

      const dynamicHex = dynamicCodec.encodeToHex({
        dynamicContentDay: 0,
        dynamicContentTime: 59710,
        dynamicContentUTCOffset: -8,
        dynamicContentDuration: 600,
      });
      expect(dynamicHex).toBe('3ba4f9a00960');
    });

    it('encodes RetailChannelData as standalone extensible enum', () => {
      const codec = new SchemaCodec(schemas['RetailChannelData'] as SchemaNode);

      const allValues = [
        'smsTicket', 'mobileApplication', 'webSite', 'ticketOffice',
        'depositaryTerminal', 'onBoardTerminal', 'ticketVendingMachine',
      ];
      for (const val of allValues) {
        const hex = codec.encodeToHex(val);
        expect(codec.decodeFromHex(hex)).toBe(val);
      }
    });

    it('encodes ProductRetailerData as standalone type', () => {
      const codec = new SchemaCodec(schemas['ProductRetailerData'] as SchemaNode);

      const value = {
        retailChannel: 'ticketVendingMachine',
        retailGeneratorId: 255,
        retailServerId: 128,
        retailerId: 2000,
        retailPointId: 100,
      };
      const hex = codec.encodeToHex(value);
      const decoded = codec.decodeFromHex(hex);
      expect(decoded).toEqual(value);
    });

    it('Intercode issuing data can embed dynamic data as OCTET STRING', () => {
      // Simulate the real-world pattern where dynamic data is encoded separately
      // and embedded as binary in another structure
      const dynamicCodec = new SchemaCodec(schemas['IntercodeDynamicData'] as SchemaNode);

      const dynamicValue = {
        dynamicContentDay: 0,
        dynamicContentTime: 59710,
        dynamicContentUTCOffset: -8,
        dynamicContentDuration: 600,
      };

      // Encode dynamic data
      const dynamicBytes = dynamicCodec.encode(dynamicValue);
      expect(dynamicBytes).toEqual(new Uint8Array([0x3B, 0xA4, 0xF9, 0xA0, 0x09, 0x60]));

      // Decode dynamic data from bytes
      const dynamicDecoded = dynamicCodec.decode(dynamicBytes);
      expect(dynamicDecoded).toEqual(dynamicValue);
    });
  });
});
