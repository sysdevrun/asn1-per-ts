import { SchemaCodec } from '../../src/schema/SchemaCodec';
import { SchemaNode } from '../../src/schema/SchemaBuilder';

describe('SchemaCodec', () => {
  describe('encode / decode round-trip', () => {
    it('handles BOOLEAN', () => {
      const codec = new SchemaCodec({ type: 'BOOLEAN' });
      const encoded = codec.encode(true);
      expect(encoded.length).toBe(1);
      expect(codec.decode(encoded)).toBe(true);
    });

    it('handles INTEGER', () => {
      const codec = new SchemaCodec({ type: 'INTEGER', min: 0, max: 255 });
      const encoded = codec.encode(200);
      expect(codec.decode(encoded)).toBe(200);
    });

    it('handles SEQUENCE', () => {
      const schema: SchemaNode = {
        type: 'SEQUENCE',
        fields: [
          { name: 'name', schema: { type: 'VisibleString', alphabet: 'ABCDEF', minSize: 1, maxSize: 10 } },
          { name: 'value', schema: { type: 'INTEGER', min: 0, max: 1000 } },
          { name: 'active', schema: { type: 'BOOLEAN' } },
        ],
      };
      const codec = new SchemaCodec(schema);
      const value = { name: 'ABC', value: 500, active: true };
      const encoded = codec.encode(value);
      expect(codec.decode(encoded)).toEqual(value);
    });
  });

  describe('encodeToHex / decodeFromHex', () => {
    it('round-trips via hex strings', () => {
      const codec = new SchemaCodec({ type: 'INTEGER', min: 0, max: 255 });
      const hex = codec.encodeToHex(42);
      expect(typeof hex).toBe('string');
      expect(codec.decodeFromHex(hex)).toBe(42);
    });

    it('hex round-trip for complex structure', () => {
      const schema: SchemaNode = {
        type: 'SEQUENCE',
        fields: [
          { name: 'x', schema: { type: 'INTEGER', min: 0, max: 7 } },
          { name: 'y', schema: { type: 'BOOLEAN' } },
        ],
      };
      const codec = new SchemaCodec(schema);
      const value = { x: 5, y: true };
      const hex = codec.encodeToHex(value);
      expect(codec.decodeFromHex(hex)).toEqual(value);
    });
  });

  describe('codec property', () => {
    it('exposes the underlying codec', () => {
      const sc = new SchemaCodec({ type: 'BOOLEAN' });
      expect(sc.codec).toBeDefined();
    });
  });

  describe('validation', () => {
    it('throws when encoding value that violates constraints', () => {
      const codec = new SchemaCodec({ type: 'INTEGER', min: 0, max: 7 });
      expect(() => codec.encode(8)).toThrow();
    });

    it('throws for missing sequence fields', () => {
      const codec = new SchemaCodec({
        type: 'SEQUENCE',
        fields: [
          { name: 'a', schema: { type: 'BOOLEAN' } },
          { name: 'b', schema: { type: 'BOOLEAN' } },
        ],
      });
      expect(() => codec.encode({ a: true })).toThrow();
    });
  });

  describe('complex real-world schema', () => {
    it('handles a message-like structure', () => {
      const schema: SchemaNode = {
        type: 'SEQUENCE',
        fields: [
          {
            name: 'messageType',
            schema: {
              type: 'ENUMERATED',
              values: ['request', 'response', 'notification'],
            },
          },
          {
            name: 'sequenceNumber',
            schema: { type: 'INTEGER', min: 0, max: 65535 },
          },
          {
            name: 'payload',
            schema: {
              type: 'CHOICE',
              alternatives: [
                {
                  name: 'text',
                  schema: { type: 'VisibleString', minSize: 0, maxSize: 100 },
                },
                {
                  name: 'data',
                  schema: { type: 'OCTET STRING', minSize: 0, maxSize: 256 },
                },
              ],
            },
          },
          {
            name: 'priority',
            schema: { type: 'INTEGER', min: 1, max: 10 },
            optional: true,
          },
        ],
      };

      const codec = new SchemaCodec(schema);

      // With optional field
      const msg1 = {
        messageType: 'request',
        sequenceNumber: 42,
        payload: { key: 'text', value: 'Hello' },
        priority: 5,
      };
      const hex1 = codec.encodeToHex(msg1);
      expect(codec.decodeFromHex(hex1)).toEqual(msg1);

      // Without optional field
      const msg2 = {
        messageType: 'response',
        sequenceNumber: 100,
        payload: { key: 'data', value: new Uint8Array([1, 2, 3]) },
      };
      const hex2 = codec.encodeToHex(msg2);
      expect(codec.decodeFromHex(hex2)).toEqual(msg2);
    });
  });
});
