import { SchemaCodec } from '../../src/schema/SchemaCodec';
import { SchemaNode } from '../../src/schema/SchemaBuilder';

describe('Schema document encoding', () => {
  const schema: SchemaNode = {
    type: 'SEQUENCE',
    fields: [
      {
        name: 'id',
        schema: { type: 'INTEGER', min: 0, max: 255 },
        defaultValue: 5,
      },
      {
        name: 'name',
        schema: { type: 'IA5String', minSize: 0, maxSize: 64 },
        defaultValue: 'hello',
      },
    ],
  };

  const codec = new SchemaCodec(schema);

  it('encodes document with all default values (id=5, name="hello")', () => {
    const doc1 = { id: 5, name: 'hello' };
    const hex1 = codec.encodeToHex(doc1);
    console.log('Document 1 (defaults):', doc1);
    console.log('Encoded hex:', hex1);
    console.log('Encoded bytes:', hex1.length / 2);

    // Both fields match defaults, so preamble bits are 00 and no field data is encoded
    const decoded1 = codec.decodeFromHex(hex1);
    expect(decoded1).toEqual(doc1);
  });

  it('encodes document with non-default values (id=42, name="world")', () => {
    const doc2 = { id: 42, name: 'world' };
    const hex2 = codec.encodeToHex(doc2);
    console.log('Document 2 (non-defaults):', doc2);
    console.log('Encoded hex:', hex2);
    console.log('Encoded bytes:', hex2.length / 2);

    // Both fields differ from defaults, so preamble bits are 11 and both are encoded
    const decoded2 = codec.decodeFromHex(hex2);
    expect(decoded2).toEqual(doc2);
  });

  it('produces smaller encoding when values match defaults', () => {
    const hexDefaults = codec.encodeToHex({ id: 5, name: 'hello' });
    const hexNonDefaults = codec.encodeToHex({ id: 42, name: 'world' });

    // Default values should produce a smaller encoding since fields are omitted
    expect(hexDefaults.length).toBeLessThan(hexNonDefaults.length);
  });

  describe('decoding', () => {
    it('decodes hex "00" to default values (id=5, name="hello")', () => {
      const decoded = codec.decodeFromHex('00');
      expect(decoded).toEqual({ id: 5, name: 'hello' });
    });

    it('decodes hex "ca82f7dfcb6640" to (id=42, name="world")', () => {
      const decoded = codec.decodeFromHex('ca82f7dfcb6640');
      expect(decoded).toEqual({ id: 42, name: 'world' });
    });

    it('decodes from Uint8Array with default values', () => {
      const data = new Uint8Array([0x00]);
      const decoded = codec.decode(data);
      expect(decoded).toEqual({ id: 5, name: 'hello' });
    });

    it('decodes from Uint8Array with non-default values', () => {
      const data = new Uint8Array([0xca, 0x82, 0xf7, 0xdf, 0xcb, 0x66, 0x40]);
      const decoded = codec.decode(data);
      expect(decoded).toEqual({ id: 42, name: 'world' });
    });

    it('decodes when only id differs from default', () => {
      const doc = { id: 100, name: 'hello' };
      const hex = codec.encodeToHex(doc);
      const decoded = codec.decodeFromHex(hex);
      expect(decoded).toEqual(doc);
    });

    it('decodes when only name differs from default', () => {
      const doc = { id: 5, name: 'test' };
      const hex = codec.encodeToHex(doc);
      const decoded = codec.decodeFromHex(hex);
      expect(decoded).toEqual(doc);
    });
  });
});

describe('Schema versioning with extension marker', () => {
  // v1: SEQUENCE { id INTEGER, ... }
  const schemaV1: SchemaNode = {
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    ],
    extensionFields: [],
  };

  // v2: SEQUENCE { id INTEGER, ..., name IA5String }
  const schemaV2: SchemaNode = {
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    ],
    extensionFields: [
      { name: 'name', schema: { type: 'IA5String', minSize: 0, maxSize: 64 } },
    ],
  };

  const codecV1 = new SchemaCodec(schemaV1);
  const codecV2 = new SchemaCodec(schemaV2);

  describe('encode {id: 42} with v1', () => {
    it('round-trips with v1', () => {
      const doc = { id: 42 };
      const hex = codecV1.encodeToHex(doc);
      console.log('v1 encode {id:42} hex:', hex);
      const decoded = codecV1.decodeFromHex(hex);
      expect(decoded).toEqual(doc);
    });
  });

  describe('encode {id: 42} with v2', () => {
    it('round-trips with v2 (no extension present)', () => {
      const doc = { id: 42 };
      const hex = codecV2.encodeToHex(doc);
      console.log('v2 encode {id:42} hex:', hex);
      const decoded = codecV2.decodeFromHex(hex);
      expect(decoded).toEqual(doc);
    });
  });

  describe('encode {id: 100, name: "world"} with v2', () => {
    it('round-trips with v2', () => {
      const doc = { id: 100, name: 'world' };
      const hex = codecV2.encodeToHex(doc);
      console.log('v2 encode {id:100,name:"world"} hex:', hex);
      const decoded = codecV2.decodeFromHex(hex);
      expect(decoded).toEqual(doc);
    });

    it('decodes with v1 (forward compatibility, unknown extensions skipped)', () => {
      const doc = { id: 100, name: 'world' };
      const hex = codecV2.encodeToHex(doc);
      console.log('v2 encoded hex decoded by v1:', hex);

      // v1 should decode the root field and silently skip the unknown extension
      const decoded = codecV1.decodeFromHex(hex);
      expect(decoded).toEqual({ id: 100 });
    });
  });

  describe('v1 and v2 produce same encoding for root-only data', () => {
    it('both encode {id: 42} identically when no extensions present', () => {
      const doc = { id: 42 };
      const hexV1 = codecV1.encodeToHex(doc);
      const hexV2 = codecV2.encodeToHex(doc);
      // Both are extensible, no extensions present -> same encoding
      expect(hexV1).toEqual(hexV2);
    });
  });
});

describe('Extension marker position affects encoding', () => {
  const doc = { id: 100, name: 'world' };

  // name is a ROOT field (before the extension marker)
  const schemaNameInRoot: SchemaNode = {
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      { name: 'name', schema: { type: 'IA5String', minSize: 0, maxSize: 64 } },
    ],
    extensionFields: [],
  };

  // name is an EXTENSION field (after the extension marker)
  const schemaNameInExt: SchemaNode = {
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    ],
    extensionFields: [
      { name: 'name', schema: { type: 'IA5String', minSize: 0, maxSize: 64 } },
    ],
  };

  const codecRoot = new SchemaCodec(schemaNameInRoot);
  const codecExt = new SchemaCodec(schemaNameInExt);

  it('root encoding is more compact than extension encoding', () => {
    const hexRoot = codecRoot.encodeToHex(doc);
    const hexExt = codecExt.encodeToHex(doc);
    console.log('name as root field    hex:', hexRoot, `(${hexRoot.length / 2} bytes)`);
    console.log('name as extension field hex:', hexExt, `(${hexExt.length / 2} bytes)`);

    // Extension encoding is larger due to open type wrapper overhead
    expect(hexRoot.length).toBeLessThan(hexExt.length);
  });

  it('both round-trip correctly despite different encodings', () => {
    const hexRoot = codecRoot.encodeToHex(doc);
    const hexExt = codecExt.encodeToHex(doc);

    expect(codecRoot.decodeFromHex(hexRoot)).toEqual(doc);
    expect(codecExt.decodeFromHex(hexExt)).toEqual(doc);
  });

  it('encodings are NOT interchangeable between schemas', () => {
    const hexRoot = codecRoot.encodeToHex(doc);
    const hexExt = codecExt.encodeToHex(doc);

    // They produce different bit layouts, so cross-decoding gives wrong results
    expect(hexRoot).not.toEqual(hexExt);
  });
});
