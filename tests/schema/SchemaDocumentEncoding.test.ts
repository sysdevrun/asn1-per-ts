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
