import { SchemaCodec } from '../../src/schema/SchemaCodec';
import { stripMetadata } from '../../src/codecs/stripMetadata';
import type { DecodedNode } from '../../src/codecs/DecodedNode';
import { SequenceCodec } from '../../src/codecs/SequenceCodec';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';

describe('SchemaCodec.decodeWithMetadata', () => {
  test('decodes from Uint8Array with metadata', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'active', schema: { type: 'BOOLEAN' } },
      ],
    });

    const encoded = codec.encode({ id: 42, active: true });
    const node = codec.decodeWithMetadata(encoded);

    expect(node.meta.bitOffset).toBe(0);
    expect(node.meta.codec).toBeInstanceOf(SequenceCodec);

    const fields = node.value as Record<string, DecodedNode>;
    expect(fields.id.value).toBe(42);
    expect(fields.id.meta.codec).toBeInstanceOf(IntegerCodec);
    expect(fields.active.value).toBe(true);
    expect(fields.active.meta.codec).toBeInstanceOf(BooleanCodec);
  });

  test('decodeFromHexWithMetadata', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'active', schema: { type: 'BOOLEAN' } },
      ],
    });

    const hex = codec.encodeToHex({ id: 42, active: true });
    const node = codec.decodeFromHexWithMetadata(hex);

    expect(node.meta.bitOffset).toBe(0);
    const fields = node.value as Record<string, DecodedNode>;
    expect(fields.id.value).toBe(42);
    expect(fields.active.value).toBe(true);
  });

  test('stripMetadata produces same result as decode', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'active', schema: { type: 'BOOLEAN' } },
        { name: 'status', schema: { type: 'ENUMERATED', values: ['pending', 'approved', 'rejected'] } },
      ],
    });

    const original = { id: 42, active: true, status: 'approved' };
    const encoded = codec.encode(original);

    const decoded = codec.decode(encoded);
    const metadataNode = codec.decodeWithMetadata(encoded);
    const stripped = stripMetadata(metadataNode);

    expect(stripped).toEqual(decoded);
  });

  test('complex schema with nested types', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 65535 } },
        { name: 'tags', schema: {
          type: 'SEQUENCE OF',
          item: { type: 'IA5String', minSize: 1, maxSize: 20 },
          minSize: 0,
          maxSize: 5,
        }},
        { name: 'type', schema: {
          type: 'CHOICE',
          alternatives: [
            { name: 'simple', schema: { type: 'BOOLEAN' } },
            { name: 'complex', schema: { type: 'INTEGER', min: 0, max: 1000 } },
          ],
        }},
      ],
    });

    const original = {
      id: 100,
      tags: ['foo', 'bar'],
      type: { key: 'complex', value: 500 },
    };

    const encoded = codec.encode(original);
    const decoded = codec.decode(encoded);
    const metadataNode = codec.decodeWithMetadata(encoded);
    const stripped = stripMetadata(metadataNode);

    expect(stripped).toEqual(decoded);
  });

  test('schema with optional and default fields', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'name', schema: { type: 'IA5String', minSize: 1, maxSize: 50 }, optional: true },
        { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
      ],
    });

    // All fields present
    const val1 = { id: 5, name: 'hello', version: 3 };
    const enc1 = codec.encode(val1);
    expect(stripMetadata(codec.decodeWithMetadata(enc1))).toEqual(codec.decode(enc1));

    // Optional absent, default used
    const val2 = { id: 5 };
    const enc2 = codec.encode(val2);
    expect(stripMetadata(codec.decodeWithMetadata(enc2))).toEqual(codec.decode(enc2));
  });

  test('schema with extension fields', () => {
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      ],
      extensionFields: [
        { name: 'name', schema: { type: 'IA5String', minSize: 1, maxSize: 50 } },
      ],
    });

    // Without extension
    const enc1 = codec.encode({ id: 42 });
    expect(stripMetadata(codec.decodeWithMetadata(enc1))).toEqual(codec.decode(enc1));

    // With extension
    const enc2 = codec.encode({ id: 42, name: 'world' });
    expect(stripMetadata(codec.decodeWithMetadata(enc2))).toEqual(codec.decode(enc2));
  });
});
