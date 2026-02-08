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

  it('throws when build() encounters $ref without registry', () => {
    expect(() => SchemaBuilder.build({ type: '$ref', ref: 'SomeType' })).toThrow(
      'Cannot resolve $ref "SomeType" without a schema registry'
    );
  });

  describe('buildAll - recursive schemas', () => {
    it('resolves $ref in a simple recursive tree structure', () => {
      const schemas: Record<string, SchemaNode> = {
        TreeNode: {
          type: 'SEQUENCE',
          fields: [
            { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
            {
              name: 'children',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'TreeNode' },
                minSize: 0,
                maxSize: 10,
              },
              optional: true,
            },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      expect(codecs['TreeNode']).toBeDefined();
    });

    it('encodes and decodes a leaf node (no children)', () => {
      const schemas: Record<string, SchemaNode> = {
        TreeNode: {
          type: 'SEQUENCE',
          fields: [
            { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
            {
              name: 'children',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'TreeNode' },
                minSize: 0,
                maxSize: 10,
              },
              optional: true,
            },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const codec = codecs['TreeNode'];

      const leaf = { value: 42 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, leaf);
      buf.reset();
      expect(codec.decode(buf)).toEqual(leaf);
    });

    it('encodes and decodes 1 level deep recursion', () => {
      const schemas: Record<string, SchemaNode> = {
        TreeNode: {
          type: 'SEQUENCE',
          fields: [
            { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
            {
              name: 'children',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'TreeNode' },
                minSize: 0,
                maxSize: 10,
              },
              optional: true,
            },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const codec = codecs['TreeNode'];

      const doc = {
        value: 1,
        children: [
          { value: 10 },
          { value: 20 },
        ],
      };
      const buf = BitBuffer.alloc();
      codec.encode(buf, doc);
      buf.reset();
      expect(codec.decode(buf)).toEqual(doc);
    });

    it('encodes and decodes 3 levels deep recursion', () => {
      const schemas: Record<string, SchemaNode> = {
        TreeNode: {
          type: 'SEQUENCE',
          fields: [
            { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
            {
              name: 'children',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'TreeNode' },
                minSize: 0,
                maxSize: 10,
              },
              optional: true,
            },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const codec = codecs['TreeNode'];

      // Level 0: root (value=1)
      //   Level 1: child A (value=10)
      //     Level 2: grandchild A1 (value=100)
      //       Level 3: great-grandchild A1a (value=200, leaf)
      //       Level 3: great-grandchild A1b (value=201, leaf)
      //     Level 2: grandchild A2 (value=101, leaf)
      //   Level 1: child B (value=20, leaf)
      const doc = {
        value: 1,
        children: [
          {
            value: 10,
            children: [
              {
                value: 100,
                children: [
                  { value: 200 },
                  { value: 201 },
                ],
              },
              { value: 101 },
            ],
          },
          { value: 20 },
        ],
      };

      const buf = BitBuffer.alloc();
      codec.encode(buf, doc);
      buf.reset();
      const decoded = codec.decode(buf);
      expect(decoded).toEqual(doc);
    });

    it('encodes and decodes multiple recursive fields (ViaStation-like)', () => {
      const schemas: Record<string, SchemaNode> = {
        ViaStation: {
          type: 'SEQUENCE',
          fields: [
            { name: 'stationId', schema: { type: 'INTEGER', min: 1, max: 9999 } },
            {
              name: 'alternativeRoutes',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'ViaStation' },
                minSize: 0,
                maxSize: 5,
              },
              optional: true,
            },
            {
              name: 'route',
              schema: {
                type: 'SEQUENCE OF',
                item: { type: '$ref', ref: 'ViaStation' },
                minSize: 0,
                maxSize: 5,
              },
              optional: true,
            },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const codec = codecs['ViaStation'];

      // 3 levels deep:
      // Root station 1000
      //   route: [station 2000 -> route: [station 3000 -> alternativeRoutes: [station 4000, station 4001]]]
      const doc = {
        stationId: 1000,
        route: [
          {
            stationId: 2000,
            route: [
              {
                stationId: 3000,
                alternativeRoutes: [
                  { stationId: 4000 },
                  { stationId: 4001 },
                ],
              },
            ],
          },
        ],
      };

      const buf = BitBuffer.alloc();
      codec.encode(buf, doc);
      buf.reset();
      const decoded = codec.decode(buf);
      expect(decoded).toEqual(doc);
    });

    it('resolves $ref across multiple types in the registry', () => {
      const schemas: Record<string, SchemaNode> = {
        Container: {
          type: 'SEQUENCE',
          fields: [
            { name: 'label', schema: { type: 'IA5String' } },
            { name: 'item', schema: { type: '$ref', ref: 'Item' } },
          ],
        },
        Item: {
          type: 'SEQUENCE',
          fields: [
            { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const codec = codecs['Container'];

      const doc = { label: 'test', item: { id: 42 } };
      const buf = BitBuffer.alloc();
      codec.encode(buf, doc);
      buf.reset();
      expect(codec.decode(buf)).toEqual(doc);
    });

    it('throws for unresolved $ref', () => {
      const schemas: Record<string, SchemaNode> = {
        MyType: {
          type: 'SEQUENCE',
          fields: [
            { name: 'data', schema: { type: '$ref', ref: 'NonExistent' } },
          ],
        },
      };

      const codecs = SchemaBuilder.buildAll(schemas);
      const buf = BitBuffer.alloc();
      // LazyCodec should throw when trying to resolve
      expect(() => codecs['MyType'].encode(buf, { data: 'anything' })).toThrow('Unresolved $ref: "NonExistent"');
    });
  });
});
