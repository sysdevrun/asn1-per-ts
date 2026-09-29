import { asn, SchemaCodec, generateTypeScript } from '../../src/index.js';
import type { BitStringValue, DecodedNode, SchemaFor, TypeOf } from '../../src/index.js';

/** Exact type equality, so an assertion cannot pass just because a side is `any`. */
type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2
  ? true
  : false;
type Expect<T extends true> = T;

describe('asn DSL — primitives', () => {
  it('maps each builder to its decoded type', () => {
    type Cases = [
      Expect<Equal<TypeOf<ReturnType<typeof asn.boolean>>, boolean>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.null>>, null>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.integer>>, number>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.octetString>>, Uint8Array>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.bitString>>, BitStringValue>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.objectIdentifier>>, string>>,
      Expect<Equal<TypeOf<ReturnType<typeof asn.utf8String>>, string>>,
    ];
    const cases: Cases = [true, true, true, true, true, true, true];
    expect(cases).toHaveLength(7);
  });

  it('narrows ENUMERATED to the union of its values', () => {
    const plain = asn.enumerated(['a', 'b']);
    const extended = asn.enumerated(['a', 'b'], { extensionValues: ['c'] });
    type Cases = [
      Expect<Equal<TypeOf<typeof plain>, 'a' | 'b'>>,
      Expect<Equal<TypeOf<typeof extended>, 'a' | 'b' | 'c'>>,
    ];
    const cases: Cases = [true, true];
    expect(cases).toHaveLength(2);
  });
});

describe('asn DSL — SEQUENCE', () => {
  const Ticket = asn.sequence({
    id: asn.integer({ min: 0, max: 255 }),
    nickname: asn.ia5String({ minSize: 1, maxSize: 32 }).optional(),
    version: asn.integer({ min: 0, max: 10 }).default(1),
  });

  it('makes OPTIONAL optional and DEFAULT required after decoding', () => {
    type Case = Expect<
      Equal<TypeOf<typeof Ticket>, { id: number; version: number; nickname?: string }>
    >;
    const c: Case = true;
    expect(c).toBe(true);
  });

  it('lets DEFAULT fields be omitted when encoding', () => {
    const codec = asn.codec(Ticket);
    type Case = Expect<
      Equal<
        Parameters<typeof codec.encode>[0],
        { id: number; nickname?: string; version?: number }
      >
    >;
    const c: Case = true;

    const decoded = codec.decode(codec.encode({ id: 5 }));
    expect(decoded).toEqual({ id: 5, version: 1 });
    const version: number = decoded.version;
    expect(version).toBe(1);
    expect(c).toBe(true);
  });

  it('marks extension additions optional', () => {
    const Extensible = asn.sequence(
      { id: asn.integer({ min: 0, max: 255 }) },
      { extensions: { note: asn.utf8String() } },
    );
    type Case = Expect<Equal<TypeOf<typeof Extensible>, { id: number; note?: string }>>;
    const c: Case = true;

    const codec = asn.codec(Extensible);
    expect(codec.decode(codec.encode({ id: 1, note: 'hi' }))).toEqual({ id: 1, note: 'hi' });
    expect(c).toBe(true);
  });

  it('refuses field names JavaScript would reorder', () => {
    // Object key order is the PER encoding order, and integer-like keys are
    // hoisted by the engine — a silently wrong encoding rather than an error.
    expect(() => asn.sequence({ '0': asn.boolean(), b: asn.boolean() })).toThrow(/array index/);
  });
});

describe('asn DSL — CHOICE', () => {
  const Payload = asn.choice({
    text: asn.utf8String(),
    data: asn.octetString({ maxSize: 8 }),
  });

  it('produces a discriminated union keyed on the alternative name', () => {
    type Case = Expect<
      Equal<
        TypeOf<typeof Payload>,
        { key: 'text'; value: string } | { key: 'data'; value: Uint8Array }
      >
    >;
    const c: Case = true;
    expect(c).toBe(true);
  });

  it('narrows the value when the key is checked', () => {
    const codec = asn.codec(Payload);
    const decoded = codec.decode(codec.encode({ key: 'text', value: 'hi' }));
    if (decoded.key === 'text') {
      expect(decoded.value.toUpperCase()).toBe('HI');
    } else {
      throw new Error('expected the text alternative');
    }
  });
});

describe('asn DSL — recursion', () => {
  interface Tree {
    value: number;
    children: Tree[];
  }

  // No annotation needed: asn.ref<Tree> supplies the type the schema infers from.
  const Tree = asn.sequence({
    value: asn.integer({ min: 0, max: 255 }),
    children: asn.sequenceOf(asn.ref<Tree>('Tree')),
  });

  it('round-trips a recursive value', () => {
    const codecs = asn.compile({ Tree });
    const value: Tree = { value: 1, children: [{ value: 2, children: [] }] };
    expect(codecs.Tree.decode(codecs.Tree.encode(value))).toEqual(value);
  });

  it('accepts the optional SchemaFor annotation as a check', () => {
    const annotated: SchemaFor<Tree> = Tree;
    expect(annotated.node.type).toBe('SEQUENCE');
  });
});

describe('asn DSL — metadata trees stay typed', () => {
  const Ticket = asn.sequence({
    id: asn.integer({ min: 0, max: 255 }),
    nickname: asn.ia5String().optional(),
  });

  it('types every node of the tree', () => {
    const codec = asn.codec(Ticket);
    type Expected = DecodedNode<{
      id: DecodedNode<number>;
      nickname: DecodedNode<string | undefined>;
    }>;
    type Case = Expect<Equal<ReturnType<typeof codec.decodeWithMetadata>, Expected>>;
    const c: Case = true;

    const tree = codec.decodeWithMetadata(codec.encode({ id: 7 }));
    expect(tree.value.id.value).toBe(7);
    expect(tree.value.id.meta.bitLength).toBe(8);
    expect(tree.value.nickname.value).toBeUndefined();
    expect(c).toBe(true);
  });
});

describe('asn DSL — no widening trap', () => {
  it('keeps types through plain consts and reuse', () => {
    // The literal API loses these types unless every value is `as const`.
    const shared = asn.integer({ min: 0, max: 10 });
    const status = asn.enumerated(['on', 'off']);
    const Outer = asn.sequence({ a: shared, b: shared, s: status });

    const codec = asn.codec(Outer);
    const value = { a: 1, b: 2, s: 'on' as const };
    expect(codec.decode(codec.encode(value))).toEqual(value);

    type Case = Expect<Equal<TypeOf<typeof Outer>, { a: number; b: number; s: 'on' | 'off' }>>;
    const c: Case = true;
    expect(c).toBe(true);
  });

  it('rejects values that do not fit', () => {
    const codec = asn.codec(asn.sequence({ s: asn.enumerated(['on', 'off']) }));
    // Never called — each @ts-expect-error is the assertion.
    const rejected = () => {
      // @ts-expect-error 'maybe' is not one of the enumeration values
      codec.encode({ s: 'maybe' });
      // @ts-expect-error 's' is mandatory
      codec.encode({});
    };
    expect(typeof rejected).toBe('function');
  });
});

describe('SchemaNode is the interchange format', () => {
  const Ticket = asn.sequence({
    id: asn.integer({ min: 0, max: 255 }),
    status: asn.enumerated(['pending', 'approved']),
    nickname: asn.ia5String({ minSize: 1, maxSize: 32 }).optional(),
    version: asn.integer({ min: 0, max: 10 }).default(1),
  });

  /** The same type written as a literal SchemaNode. */
  const literal = {
    type: 'SEQUENCE',
    fields: [
      { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
      { name: 'status', schema: { type: 'ENUMERATED', values: ['pending', 'approved'] } },
      { name: 'nickname', schema: { type: 'IA5String', minSize: 1, maxSize: 32 }, optional: true },
      { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
    ],
  } as const;

  it('the DSL emits the same SchemaNode the literal API consumes', () => {
    expect(JSON.parse(JSON.stringify(asn.toSchemaNode(Ticket)))).toEqual(
      JSON.parse(JSON.stringify(literal)),
    );
  });

  it('both front-ends produce identical bytes', () => {
    const fromDsl = asn.codec(Ticket);
    const fromLiteral = new SchemaCodec(literal);
    const value = { id: 42, status: 'approved' } as const;
    expect(fromDsl.encodeToHex(value)).toBe(fromLiteral.encodeToHex(value));
  });

  it('a DSL module feeds the code generator', () => {
    const registry = asn.toSchemaRegistry({ Ticket });
    const code = generateTypeScript(registry, { emitRuntime: false });
    expect(code).toContain('export interface Ticket {');
    expect(code).toContain('status: "pending" | "approved";');
    expect(code).toContain('nickname?: string;');
    // DEFAULT: required to decode, optional to encode.
    expect(code).toContain('export interface TicketInput {');
    expect(code).toMatch(/export interface Ticket \{[^}]*\n  version: number;/);
    expect(code).toMatch(/export interface TicketInput \{[^}]*\n  version\?: number;/);
  });
});
