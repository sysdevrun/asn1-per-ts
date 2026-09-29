# The `asn` Builder DSL

Build schemas from functions instead of object literals. The TypeScript types
ride in the value's type parameters rather than being recomputed from literal
types, which removes the widening traps of the literal API and produces much
shorter error messages.

```typescript
import { asn } from 'asn1-per-ts';

const Ticket = asn.sequence({
  id: asn.integer({ min: 0, max: 255 }),
  status: asn.enumerated(['pending', 'approved']),
  nickname: asn.ia5String({ minSize: 1, maxSize: 32 }).optional(),
  version: asn.integer({ min: 0, max: 10 }).default(1),
});

const codec = asn.codec(Ticket);

const hex = codec.encodeToHex({ id: 42, status: 'approved' });
const value = codec.decodeFromHex(hex);
//    ^? { id: number; status: 'pending' | 'approved'; version: number; nickname?: string }
```

## Why this over an inline `SchemaNode`

Both front-ends give you typed encode and decode. The DSL differs in three ways.

**No widening trap.** The literal API reads the *literal type* of the schema
object, so a schema or a value stored in a plain `const` silently loses its
types:

```typescript
// literal API — widens, and stops matching SchemaNode
const schema = { type: 'SEQUENCE', fields: [/* … */] };

// DSL — a plain const is fine, and so is reusing it
const shared = asn.integer({ min: 0, max: 10 });
const Outer = asn.sequence({ a: shared, b: shared });
```

**Shorter errors.** The literal API's types are deferred conditional types, and
TypeScript prints those by alias name rather than resolving them. Same mistake,
both APIs:

```
// literal API
not assignable to type '{ … type: InferInputChoice<{ readonly type: "CHOICE";
  readonly alternatives: readonly [...]; }, Record<...>, 12>; }'

// DSL
not assignable to type '{ … type: { key: "simple"; value: boolean }
  | { key: "complex"; value: number } }'
```

**Cheaper to compile.** On a 150-type schema the DSL costs about half the type
instantiations of the literal API. Neither is a problem at that size; generated
code (see [codegen.md](./codegen.md)) is cheaper than both.

The literal API remains the right choice when the schema *is* data — parsed
from JSON, produced by the ASN.1 parser, or round-tripped over the wire.

## Builders

| Builder | Decoded type |
|---|---|
| `asn.boolean()` | `boolean` |
| `asn.null()` | `null` |
| `asn.integer({ min, max, extensible })` | `number` |
| `asn.enumerated([...], { extensionValues })` | union of the value names |
| `asn.bitString({ fixedSize, minSize, maxSize, extensible })` | `BitStringValue` |
| `asn.octetString({ … })` | `Uint8Array` |
| `asn.objectIdentifier()` | `string` |
| `asn.ia5String({ … })` / `asn.visibleString({ … })` / `asn.utf8String({ … })` | `string` |
| `asn.sequence({ … }, { extensions })` | object |
| `asn.sequenceOf(item, { … })` | array |
| `asn.choice({ … }, { extensions })` | discriminated union |
| `asn.ref<T>(name)` | `T` |

Every builder returns a `Schema`, and every `Schema` carries `.optional()` and
`.default(value)` for use as a SEQUENCE field.

## Field order is the encoding order

PER encodes SEQUENCE components in declaration order, and the DSL takes that
order from the object's keys. JavaScript preserves insertion order for string
keys — except integer-like keys, which the engine hoists to the front. ASN.1
identifiers must begin with a lowercase letter so this cannot arise from a real
spec, but the DSL throws rather than silently producing a wrong encoding:

```typescript
asn.sequence({ '0': asn.boolean(), b: asn.boolean() });
// Error: SEQUENCE field name '0' is an array index: JavaScript would reorder it …
```

## OPTIONAL, DEFAULT and extensions

```typescript
const Ticket = asn.sequence(
  {
    id: asn.integer({ min: 0, max: 255 }),
    nickname: asn.ia5String().optional(),
    version: asn.integer({ min: 0, max: 10 }).default(1),
  },
  { extensions: { note: asn.utf8String() } },
);
```

| Field | `encode()` | `decode()` |
|---|---|---|
| `id` | required | required |
| `nickname` (`OPTIONAL`) | optional | optional |
| `version` (`DEFAULT 1`) | optional | **required** — the decoder substitutes `1` |
| `note` (extension) | optional | optional |

Pass `{ extensions: {} }` to mark a type extensible without declaring any
addition.

## CHOICE

```typescript
const Payload = asn.choice({
  text: asn.utf8String(),
  data: asn.octetString({ maxSize: 8 }),
});

const decoded = asn.codec(Payload).decodeFromHex(hex);
//    ^? { key: 'text'; value: string } | { key: 'data'; value: Uint8Array }

if (decoded.key === 'text') {
  decoded.value.toUpperCase(); // narrowed to string
}
```

## Recursion

TypeScript cannot infer a recursive type. Name it once as an interface and hand
it to `asn.ref` — the surrounding schema infers from that, so it needs no
annotation of its own:

```typescript
interface Tree {
  value: number;
  children: Tree[];
}

const Tree = asn.sequence({
  value: asn.integer({ min: 0, max: 255 }),
  children: asn.sequenceOf(asn.ref<Tree>('Tree')),
});

const codecs = asn.compile({ Tree });
const tree = codecs.Tree.decodeFromHex(hex); // Tree
```

The string passed to `asn.ref` must match the key given to `asn.compile`.

If you want the annotation anyway, as a check that the schema really describes
`Tree`, use `SchemaFor<Tree>`. The cost is that `decodeWithMetadata` on that
schema is no longer typed:

```typescript
const Tree: SchemaFor<Tree> = asn.sequence({ /* … */ });
```

## Several types at once

`asn.compile` builds one codec per entry and resolves `asn.ref` between them:

```typescript
const codecs = asn.compile({ Person, Animal, Ticket });
codecs.Person.decodeFromHex(hex);
```

`asn.codec(schema)` is the single-schema form; it cannot resolve `asn.ref`.

## Metadata trees stay typed

```typescript
const tree = codec.decodeWithMetadata(bytes);
tree.value.id.value;          // number
tree.value.id.meta.bitLength; // number
tree.value.nickname.value;    // string | undefined
```

## Going back to the interchange format

A DSL schema is a thin wrapper over the same `SchemaNode` the parser emits:

```typescript
import { asn, generateTypeScript } from 'asn1-per-ts';

asn.toSchemaNode(Ticket);              // SchemaNode
asn.toSchemaRegistry({ Ticket });      // SchemaRegistry

// which means a DSL module can feed the code generator
generateTypeScript(asn.toSchemaRegistry({ Ticket }));
```

See [typed-api.md](./typed-api.md#one-interchange-format) for how the three
front-ends fit together.
