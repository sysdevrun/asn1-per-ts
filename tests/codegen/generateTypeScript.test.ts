import { generateTypeScript } from '../../src/codegen/generateTypeScript.js';
import { buildNameMap, propertyKey, toTypeName } from '../../src/codegen/identifiers.js';
import type { SchemaRegistry } from '../../src/index.js';

const gen = (schemas: SchemaRegistry): string =>
  generateTypeScript(schemas, { emitRuntime: false });

describe('identifiers', () => {
  it('turns ASN.1 names into PascalCase TypeScript identifiers', () => {
    expect(toTypeName('Uic-RailTicketData')).toBe('UicRailTicketData');
    expect(toTypeName('Sales-Channel')).toBe('SalesChannel');
    expect(toTypeName('Envelope')).toBe('Envelope');
    expect(toTypeName('lower-case')).toBe('LowerCase');
  });

  it('escapes names that would shadow globals or the generated imports', () => {
    // A type named `TypedCodec` would shadow the generated file's own import.
    expect(toTypeName('TypedCodec')).toBe('TypedCodec_');
    expect(toTypeName('Uint8Array')).toBe('Uint8Array_');
    expect(toTypeName('String')).toBe('String_');
  });

  it('numbers names that sanitize to the same identifier', () => {
    const map = buildNameMap(['Foo-Bar', 'FooBar', 'Foo--Bar']);
    expect([...map.values()]).toEqual(['FooBar', 'FooBar2', 'FooBar3']);
  });

  it('avoids colliding with the emitted runtime values or Input aliases', () => {
    const map = buildNameMap(['Foo', 'FooInput'], ['schemas', 'codecs']);
    expect(map.get('Foo')).toBe('Foo');
    expect(map.get('FooInput')).toBe('FooInput2');
  });

  it('quotes property names that are not bare identifiers', () => {
    expect(propertyKey('issuerNum')).toBe('issuerNum');
    expect(propertyKey('issuer-num')).toBe('"issuer-num"');
  });
});

describe('generateTypeScript', () => {
  it('maps each ASN.1 type to a TypeScript type', () => {
    const out = gen({
      Prims: {
        type: 'SEQUENCE',
        fields: [
          { name: 'b', schema: { type: 'BOOLEAN' } },
          { name: 'n', schema: { type: 'NULL' } },
          { name: 'i', schema: { type: 'INTEGER', min: 0, max: 9 } },
          { name: 'o', schema: { type: 'OCTET STRING' } },
          { name: 'oid', schema: { type: 'OBJECT IDENTIFIER' } },
          { name: 's', schema: { type: 'UTF8String' } },
          { name: 'bits', schema: { type: 'BIT STRING', fixedSize: 4 } },
        ],
      },
    });
    expect(out).toContain('b: boolean;');
    expect(out).toContain('n: null;');
    expect(out).toContain('i: number;');
    expect(out).toContain('o: Uint8Array;');
    expect(out).toContain('oid: string;');
    expect(out).toContain('s: string;');
    expect(out).toContain('bits: BitStringValue;');
  });

  it('imports BitStringValue only when a BIT STRING is present', () => {
    const withBits = gen({ A: { type: 'BIT STRING', fixedSize: 4 } });
    const without = gen({ A: { type: 'BOOLEAN' } });
    expect(withBits).toContain('BitStringValue');
    expect(without).not.toContain('BitStringValue');
  });

  it('imports nothing when only types are emitted and none are needed', () => {
    // An unused import breaks a consumer building with noUnusedLocals.
    expect(gen({ A: { type: 'BOOLEAN' } })).not.toContain('import');
  });

  it('imports the runtime only when the runtime values are emitted', () => {
    const full = generateTypeScript({ A: { type: 'BOOLEAN' } });
    expect(full).toContain("import { createCodecs } from 'asn1-per-ts';");
    expect(full).toContain('SchemaRegistry, TypedCodec');
  });

  it('folds extension values into the ENUMERATED union', () => {
    const out = gen({
      Channel: { type: 'ENUMERATED', values: ['a', 'b'], extensionValues: ['c'] },
    });
    expect(out).toContain('export type Channel = "a" | "b" | "c";');
  });

  it('emits CHOICE as a discriminated union', () => {
    const out = gen({
      Payload: {
        type: 'CHOICE',
        alternatives: [
          { name: 'text', schema: { type: 'UTF8String' } },
          { name: 'raw', schema: { type: 'OCTET STRING' } },
        ],
      },
    });
    expect(out).toContain(
      'export type Payload = { key: "text"; value: string } | { key: "raw"; value: Uint8Array };',
    );
  });

  it('parenthesises union element types inside an array', () => {
    const out = gen({
      List: {
        type: 'SEQUENCE OF',
        item: {
          type: 'CHOICE',
          alternatives: [
            { name: 'a', schema: { type: 'BOOLEAN' } },
            { name: 'b', schema: { type: 'INTEGER' } },
          ],
        },
      },
    });
    expect(out).toContain('})[]');
  });

  it('marks OPTIONAL fields optional in both directions', () => {
    const out = gen({
      A: {
        type: 'SEQUENCE',
        fields: [{ name: 'x', schema: { type: 'BOOLEAN' }, optional: true }],
      },
    });
    expect(out).toContain('x?: boolean;');
    expect(out).toContain('export type AInput = A;');
  });

  it('makes DEFAULT fields required to decode and optional to encode', () => {
    const out = gen({
      A: {
        type: 'SEQUENCE',
        fields: [{ name: 'x', schema: { type: 'INTEGER', min: 0, max: 9 }, defaultValue: 1 }],
      },
    });
    expect(out).toContain('export interface A {\n  x: number;\n}');
    expect(out).toContain('export interface AInput {\n  x?: number;\n}');
  });

  it('propagates the need for an Input variant through $ref', () => {
    const out = gen({
      Inner: {
        type: 'SEQUENCE',
        fields: [{ name: 'x', schema: { type: 'INTEGER', min: 0, max: 9 }, defaultValue: 1 }],
      },
      Outer: {
        type: 'SEQUENCE',
        fields: [{ name: 'inner', schema: { type: '$ref', ref: 'Inner' } }],
      },
    });
    expect(out).toContain('export interface OuterInput {\n  inner: InnerInput;\n}');
  });

  it('terminates on $ref cycles when deciding about Input variants', () => {
    const out = gen({
      Node: {
        type: 'SEQUENCE',
        fields: [
          { name: 'kids', schema: { type: 'SEQUENCE OF', item: { type: '$ref', ref: 'Node' } } },
        ],
      },
    });
    expect(out).toContain('kids: Node[];');
    expect(out).toContain('export type NodeInput = Node;');
  });

  it('makes extension fields optional', () => {
    const out = gen({
      A: {
        type: 'SEQUENCE',
        fields: [{ name: 'x', schema: { type: 'BOOLEAN' } }],
        extensionFields: [{ name: 'y', schema: { type: 'BOOLEAN' } }],
      },
    });
    expect(out).toContain('x: boolean;');
    expect(out).toContain('y?: boolean;');
  });

  it('names a structure that matches another type instead of inlining it', () => {
    const inner = {
      type: 'SEQUENCE',
      fields: [{ name: 'x', schema: { type: 'BOOLEAN' } }],
    } as const;
    const out = gen({ Inner: inner, Outer: { type: 'SEQUENCE', fields: [{ name: 'i', schema: inner }] } });
    expect(out).toContain('i: Inner;');
  });

  it('handles an empty SEQUENCE', () => {
    expect(gen({ A: { type: 'SEQUENCE', fields: [] } })).toContain(
      'export type A = Record<never, never>;',
    );
  });

  it('emits an unresolvable $ref as unknown rather than failing', () => {
    const out = gen({
      A: { type: 'SEQUENCE', fields: [{ name: 'x', schema: { type: '$ref', ref: 'Missing' } }] },
    });
    expect(out).toContain('x: unknown;');
  });
});
