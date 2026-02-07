import { BitBuffer } from '../../src/BitBuffer';
import { SchemaBuilder, SchemaNode } from '../../src/schema/SchemaBuilder';

describe('SchemaBuilder', () => {
  it('builds BOOLEAN codec', () => {
    const codec = SchemaBuilder.build({ type: 'BOOLEAN' });
    const buf = BitBuffer.alloc();
    codec.encode(buf, true);
    buf.reset();
    expect(codec.decode(buf)).toBe(true);
  });

  it('builds NULL codec', () => {
    const codec = SchemaBuilder.build({ type: 'NULL' });
    const buf = BitBuffer.alloc();
    codec.encode(buf, null);
    buf.reset();
    expect(codec.decode(buf)).toBeNull();
  });

  it('builds INTEGER codec', () => {
    const codec = SchemaBuilder.build({ type: 'INTEGER', min: 0, max: 255 });
    const buf = BitBuffer.alloc();
    codec.encode(buf, 42);
    buf.reset();
    expect(codec.decode(buf)).toBe(42);
  });

  it('builds ENUMERATED codec', () => {
    const codec = SchemaBuilder.build({
      type: 'ENUMERATED',
      values: ['a', 'b', 'c'],
    });
    const buf = BitBuffer.alloc();
    codec.encode(buf, 'b');
    buf.reset();
    expect(codec.decode(buf)).toBe('b');
  });

  it('builds BIT STRING codec', () => {
    const codec = SchemaBuilder.build({ type: 'BIT STRING', fixedSize: 4 });
    const buf = BitBuffer.alloc();
    codec.encode(buf, { data: new Uint8Array([0b10100000]), bitLength: 4 });
    buf.reset();
    const result = codec.decode(buf) as { bitLength: number };
    expect(result.bitLength).toBe(4);
  });

  it('builds OCTET STRING codec', () => {
    const codec = SchemaBuilder.build({ type: 'OCTET STRING', fixedSize: 2 });
    const buf = BitBuffer.alloc();
    codec.encode(buf, new Uint8Array([0xAB, 0xCD]));
    buf.reset();
    expect(codec.decode(buf)).toEqual(new Uint8Array([0xAB, 0xCD]));
  });

  it('builds VisibleString codec', () => {
    const codec = SchemaBuilder.build({
      type: 'VisibleString',
      alphabet: 'ABC',
      fixedSize: 3,
    });
    const buf = BitBuffer.alloc();
    codec.encode(buf, 'BAC');
    buf.reset();
    expect(codec.decode(buf)).toBe('BAC');
  });

  it('builds CHOICE codec', () => {
    const codec = SchemaBuilder.build({
      type: 'CHOICE',
      alternatives: [
        { name: 'flag', schema: { type: 'BOOLEAN' } },
        { name: 'num', schema: { type: 'INTEGER', min: 0, max: 7 } },
      ],
    });
    const buf = BitBuffer.alloc();
    codec.encode(buf, { key: 'num', value: 5 });
    buf.reset();
    const result = codec.decode(buf) as { key: string; value: unknown };
    expect(result.key).toBe('num');
    expect(result.value).toBe(5);
  });

  it('builds SEQUENCE codec', () => {
    const codec = SchemaBuilder.build({
      type: 'SEQUENCE',
      fields: [
        { name: 'x', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'y', schema: { type: 'BOOLEAN' } },
      ],
    });
    const buf = BitBuffer.alloc();
    codec.encode(buf, { x: 100, y: false });
    buf.reset();
    expect(codec.decode(buf)).toEqual({ x: 100, y: false });
  });

  it('builds SEQUENCE OF codec', () => {
    const codec = SchemaBuilder.build({
      type: 'SEQUENCE OF',
      item: { type: 'INTEGER', min: 0, max: 3 },
      minSize: 0,
      maxSize: 5,
    });
    const buf = BitBuffer.alloc();
    codec.encode(buf, [1, 2, 3]);
    buf.reset();
    expect(codec.decode(buf)).toEqual([1, 2, 3]);
  });

  it('builds deeply nested structures', () => {
    const schema: SchemaNode = {
      type: 'SEQUENCE',
      fields: [
        {
          name: 'items',
          schema: {
            type: 'SEQUENCE OF',
            item: {
              type: 'SEQUENCE',
              fields: [
                { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
                { name: 'label', schema: { type: 'VisibleString', alphabet: 'ABCDEFGHIJ', minSize: 1, maxSize: 5 } },
              ],
            },
            minSize: 0,
            maxSize: 10,
          },
        },
        { name: 'active', schema: { type: 'BOOLEAN' } },
      ],
    };

    const codec = SchemaBuilder.build(schema);
    const value = {
      items: [
        { id: 1, label: 'ABC' },
        { id: 200, label: 'DEF' },
      ],
      active: true,
    };

    const buf = BitBuffer.alloc();
    codec.encode(buf, value);
    buf.reset();
    expect(codec.decode(buf)).toEqual(value);
  });

  it('builds from JSON string', () => {
    const json = JSON.stringify({ type: 'BOOLEAN' });
    const codec = SchemaBuilder.fromJSON(json);
    const buf = BitBuffer.alloc();
    codec.encode(buf, false);
    buf.reset();
    expect(codec.decode(buf)).toBe(false);
  });

  it('throws for unknown type', () => {
    expect(() => SchemaBuilder.build({ type: 'UNKNOWN' } as any)).toThrow();
  });
});
