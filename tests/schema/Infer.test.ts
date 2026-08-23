import {
  createCodec,
  createCodecs,
  defineSchema,
  defineSchemas,
  SchemaBuilder,
  SchemaCodec,
  stripMetadata,
} from '../../src/index.js';
import type {
  BitStringValue,
  DecodedNode,
  Infer,
  InferInput,
  InferInputRaw,
  InferMetadata,
  RawBytes,
  SchemaNode,
} from '../../src/index.js';

/**
 * Exact type equality. Unlike `extends`, this fails when the two types merely
 * overlap — so an assertion cannot pass just because one side is `any`/`unknown`.
 */
type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2
  ? true
  : false;
type Expect<T extends true> = T;

describe('Infer — primitives', () => {
  it('maps every primitive schema to its decoded type', () => {
    type Cases = [
      Expect<Equal<Infer<{ type: 'BOOLEAN' }>, boolean>>,
      Expect<Equal<Infer<{ type: 'NULL' }>, null>>,
      Expect<Equal<Infer<{ type: 'INTEGER'; min: 0; max: 255 }>, number>>,
      Expect<Equal<Infer<{ type: 'INTEGER' }>, number>>,
      Expect<Equal<Infer<{ type: 'BIT STRING'; fixedSize: 8 }>, BitStringValue>>,
      Expect<Equal<Infer<{ type: 'OCTET STRING' }>, Uint8Array>>,
      Expect<Equal<Infer<{ type: 'OBJECT IDENTIFIER' }>, string>>,
      Expect<Equal<Infer<{ type: 'IA5String'; maxSize: 10 }>, string>>,
      Expect<Equal<Infer<{ type: 'VisibleString' }>, string>>,
      Expect<Equal<Infer<{ type: 'UTF8String' }>, string>>,
    ];
    const _cases: Cases = [true, true, true, true, true, true, true, true, true, true];
    expect(_cases).toHaveLength(10);
  });

  it('narrows ENUMERATED to the union of its values', () => {
    type Plain = Infer<{ type: 'ENUMERATED'; values: readonly ['a', 'b'] }>;
    type Extended = Infer<{
      type: 'ENUMERATED';
      values: readonly ['a', 'b'];
      extensionValues: readonly ['c'];
    }>;
    type Cases = [Expect<Equal<Plain, 'a' | 'b'>>, Expect<Equal<Extended, 'a' | 'b' | 'c'>>];
    const _cases: Cases = [true, true];
    expect(_cases).toHaveLength(2);
  });
});

describe('Infer — SEQUENCE', () => {
  const schema = defineSchema({
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
      { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
    ],
    extensionFields: [{ name: 'note', schema: { type: 'UTF8String' } }],
  });

  it('makes OPTIONAL and extension fields optional, DEFAULT fields required', () => {
    // DEFAULT fields are always present after decoding: decode() substitutes
    // the default when the encoding omits them.
    type Decoded = Infer<typeof schema>;
    type Expected = {
      id: number;
      version: number;
      nickname?: string;
      note?: string;
    };
    type Case = Expect<Equal<Decoded, Expected>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('lets DEFAULT fields be omitted when encoding', () => {
    type Input = InferInput<typeof schema>;
    type Expected = {
      id: number;
      nickname?: string;
      version?: number;
      note?: string;
    };
    type Case = Expect<Equal<Input, Expected>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('admits RawBytes at any node only in the raw variant', () => {
    type Raw = InferInputRaw<typeof schema>;
    type Expected =
      | RawBytes
      | {
          id: number | RawBytes;
          nickname?: string | RawBytes;
          version?: number | RawBytes;
          note?: string | RawBytes;
        };
    type Case = Expect<Equal<Raw, Expected>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('round-trips with the inferred types at runtime', () => {
    const codec = createCodec(schema);
    const hex = codec.encodeToHex({ id: 5, nickname: 'hi' });
    const decoded = codec.decodeFromHex(hex);
    expect(decoded).toEqual({ id: 5, nickname: 'hi', version: 1 });
    // `version` is typed as required, so this compiles without a narrowing check.
    const version: number = decoded.version;
    expect(version).toBe(1);
  });
});

describe('Infer — CHOICE', () => {
  const schema = defineSchema({
    type: 'CHOICE',
    alternatives: [
      { name: 'flag', schema: { type: 'BOOLEAN' } },
      { name: 'count', schema: { type: 'INTEGER', min: 0, max: 255 } },
    ],
    extensionAlternatives: [{ name: 'label', schema: { type: 'UTF8String' } }],
  });

  it('produces a discriminated union keyed on the alternative name', () => {
    type Decoded = Infer<typeof schema>;
    type Expected =
      | { key: 'flag'; value: boolean }
      | { key: 'count'; value: number }
      | { key: 'label'; value: string };
    type Case = Expect<Equal<Decoded, Expected>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('narrows the value when the key is checked', () => {
    const codec = createCodec(schema);
    const decoded = codec.decodeFromHex(codec.encodeToHex({ key: 'count', value: 42 }));
    if (decoded.key === 'count') {
      const count: number = decoded.value;
      expect(count).toBe(42);
    } else {
      throw new Error('expected the count alternative');
    }
  });
});

describe('Infer — SEQUENCE OF and nesting', () => {
  it('infers arrays of the item type', () => {
    const schema = defineSchema({
      type: 'SEQUENCE',
      fields: [
        {
          name: 'points',
          schema: {
            type: 'SEQUENCE OF',
            item: {
              type: 'SEQUENCE',
              fields: [
                { name: 'x', schema: { type: 'INTEGER', min: 0, max: 100 } },
                { name: 'y', schema: { type: 'INTEGER', min: 0, max: 100 } },
              ],
            },
          },
        },
      ],
    });
    type Decoded = Infer<typeof schema>;
    type Case = Expect<Equal<Decoded, { points: { x: number; y: number }[] }>>;
    const _case: Case = true;

    const codec = createCodec(schema);
    const decoded = codec.decodeFromHex(codec.encodeToHex({ points: [{ x: 1, y: 2 }] }));
    expect(decoded.points[0].x).toBe(1);
    expect(_case).toBe(true);
  });
});

describe('Infer — $ref resolution through a registry', () => {
  const registry = defineSchemas({
    Person: {
      type: 'SEQUENCE',
      fields: [
        { name: 'name', schema: { type: 'UTF8String' } },
        { name: 'pet', schema: { type: '$ref', ref: 'Animal' }, optional: true },
      ],
    },
    Animal: {
      type: 'SEQUENCE',
      fields: [{ name: 'legs', schema: { type: 'INTEGER', min: 0, max: 8 } }],
    },
  });

  it('expands $ref against the registry', () => {
    type Person = Infer<(typeof registry)['Person'], typeof registry>;
    type Case = Expect<Equal<Person, { name: string; pet?: { legs: number } }>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('builds runtime codecs whose decoded values match the inferred types', () => {
    const codecs = createCodecs(registry);
    const hex = codecs.Person.encodeToHex({ name: 'Ada', pet: { legs: 4 } });
    const person = codecs.Person.decodeFromHex(hex);
    expect(person).toEqual({ name: 'Ada', pet: { legs: 4 } });
    const legs: number | undefined = person.pet?.legs;
    expect(legs).toBe(4);
  });

  it('terminates on recursive schemas instead of expanding forever', () => {
    const recursive = defineSchemas({
      Tree: {
        type: 'SEQUENCE',
        fields: [
          { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
          {
            name: 'children',
            schema: { type: 'SEQUENCE OF', item: { type: '$ref', ref: 'Tree' } },
          },
        ],
      },
    });
    // Expansion stops after the depth budget, leaving `unknown` at the deepest
    // level instead of recursing forever. The budget defaults to DefaultRefDepth;
    // it is lowered here so the resulting type stays small enough to spell out.
    type Tree = Infer<(typeof recursive)['Tree'], typeof recursive, 1>;
    type Case = Expect<Equal<Tree, { value: number; children: { value: number; children: unknown[] }[] }>>;
    const _case: Case = true;

    const codecs = createCodecs(recursive);
    const hex = codecs.Tree.encodeToHex({ value: 1, children: [{ value: 2, children: [] }] });
    expect(codecs.Tree.decodeFromHex(hex)).toEqual({
      value: 1,
      children: [{ value: 2, children: [] }],
    });
    expect(_case).toBe(true);
  });
});

describe('InferMetadata and stripMetadata', () => {
  const schema = defineSchema({
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
    ],
  });

  it('types every node of the metadata tree', () => {
    type Tree = InferMetadata<typeof schema>;
    type Expected = DecodedNode<{
      id: DecodedNode<number>;
      nickname: DecodedNode<string | undefined>;
    }>;
    type Case = Expect<Equal<Tree, Expected>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });

  it('gives stripMetadata the same type as decode', () => {
    type Stripped = ReturnType<typeof stripMetadata<InferMetadata<typeof schema>>>;
    type Case = Expect<Equal<Stripped, Infer<typeof schema>>>;
    const _case: Case = true;

    const codec = createCodec(schema);
    const bytes = codec.encode({ id: 7 });
    const tree = codec.decodeWithMetadata(bytes);
    expect(tree.value.id.value).toBe(7);
    expect(tree.value.id.meta.bitLength).toBe(8);
    expect(stripMetadata(tree)).toEqual(codec.decode(bytes));
    expect(_case).toBe(true);
  });
});

describe('backward compatibility with runtime-only schemas', () => {
  it('keeps unknown when the schema is the wide SchemaNode union', () => {
    // Returned from a function so TypeScript cannot narrow it back down to the
    // literal — this is what a schema parsed from JSON at runtime looks like.
    const loadSchema = (): SchemaNode => ({
      type: 'SEQUENCE',
      fields: [{ name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } }],
    });
    const codec = new SchemaCodec(loadSchema());
    type Cases = [
      Expect<Equal<ReturnType<typeof codec.decode>, unknown>>,
      Expect<Equal<Parameters<typeof codec.encode>[0], unknown>>,
      Expect<Equal<ReturnType<typeof codec.decodeWithMetadata>, DecodedNode>>,
      Expect<Equal<Infer<SchemaNode>, unknown>>,
      Expect<Equal<InferInput<SchemaNode>, unknown>>,
    ];
    const _cases: Cases = [true, true, true, true, true];

    expect(codec.decode(codec.encode({ id: 3 }))).toEqual({ id: 3 });
    expect(_cases).toHaveLength(5);
  });

  it('keeps SchemaBuilder.build usable with a runtime schema', () => {
    const loadSchema = (): SchemaNode => ({ type: 'BOOLEAN' });
    const codec = SchemaBuilder.build(loadSchema());
    type Case = Expect<Equal<ReturnType<typeof codec.decode>, unknown>>;
    const _case: Case = true;
    expect(_case).toBe(true);
  });
});

describe('typed encoding rejects values that do not fit the schema', () => {
  const codec = createCodec({
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      { name: 'status', schema: { type: 'ENUMERATED', values: ['on', 'off'] } },
      {
        name: 'payload',
        schema: {
          type: 'CHOICE',
          alternatives: [
            { name: 'text', schema: { type: 'UTF8String' } },
            { name: 'raw', schema: { type: 'OCTET STRING' } },
          ],
        },
      },
    ],
  });

  it('reports the mismatch at compile time', () => {
    // Never invoked: each @ts-expect-error is the assertion. If the typed API
    // ever stops rejecting one of these values, the directive becomes unused
    // and the build fails.
    const rejected = () => {
      // @ts-expect-error 'id' must be a number
      codec.encode({ id: 'x', status: 'on', payload: { key: 'text', value: 'a' } });
      // @ts-expect-error 'nope' is not one of the enumeration values
      codec.encode({ id: 1, status: 'nope', payload: { key: 'text', value: 'a' } });
      // @ts-expect-error the 'text' alternative carries a string, not a Uint8Array
      codec.encode({ id: 1, status: 'on', payload: { key: 'text', value: new Uint8Array() } });
      // @ts-expect-error 'missing' is not an alternative of the CHOICE
      codec.encode({ id: 1, status: 'on', payload: { key: 'missing', value: 'a' } });
      // @ts-expect-error 'status' is mandatory
      codec.encode({ id: 1, payload: { key: 'text', value: 'a' } });
    };
    expect(typeof rejected).toBe('function');
  });

  it('still encodes a well-typed value', () => {
    const hex = codec.encodeToHex({ id: 1, status: 'on', payload: { key: 'text', value: 'a' } });
    const decoded = codec.decodeFromHex(hex);
    expect(decoded).toEqual({ id: 1, status: 'on', payload: { key: 'text', value: 'a' } });
  });

  it('accepts pre-encoded RawBytes through the raw view', () => {
    const inner = createCodec({ type: 'UTF8String' });
    const hex = codec.raw.encodeToHex({
      id: 1,
      status: 'on',
      payload: { key: 'text', value: inner.encodeToRawBytes('a') },
    });
    expect(codec.decodeFromHex(hex)).toEqual({ id: 1, status: 'on', payload: { key: 'text', value: 'a' } });
  });

  it('keeps RawBytes out of the strict encoder', () => {
    const inner = createCodec({ type: 'UTF8String' });
    const pre = inner.encodeToRawBytes('a');
    // Never called — the @ts-expect-error is the assertion. Allowing RawBytes at
    // every node doubled the size of every encode error message.
    const rejected = () => {
      // @ts-expect-error RawBytes needs the `raw` view
      codec.encodeToHex({ id: 1, status: 'on', payload: { key: 'text', value: pre } });
    };
    expect(typeof rejected).toBe('function');
  });
});
