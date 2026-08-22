# Typed Encoding and Decoding

TypeScript derives the encoded and decoded types from the schema itself, so
`decode()` returns a real object type instead of `unknown` and `encode()`
rejects values that do not fit the schema.

This is entirely a compile-time feature: no validation code runs, no runtime
dependency is added, and the emitted JavaScript is unchanged.

## The short version

```typescript
import { SchemaCodec } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'status', schema: { type: 'ENUMERATED', values: ['pending', 'approved'] } },
    { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
  ],
});

const hex = codec.encodeToHex({ id: 42, status: 'approved' });

const decoded = codec.decodeFromHex(hex);
//    ^? { id: number; status: 'pending' | 'approved'; nickname?: string }

decoded.status;   // 'pending' | 'approved'
decoded.nickname; // string | undefined

codec.encodeToHex({ id: 1, status: 'rejected' });
//                         ~~~~~~~~~~~~~~~~~~ not assignable to 'pending' | 'approved'
```

Nothing needs to be declared twice: the schema *is* the type.

## How it works

`SchemaCodec` takes the schema as a `const` type parameter, so the object
literal keeps its literal types (`'INTEGER'`, `'id'`, `0`, `255`) instead of
widening to `string` and `number`. The `Infer<S>` conditional type then walks
that literal type and computes the decoded TypeScript type.

Three type helpers are exported, one per direction:

| Helper | Describes | Used by |
|---|---|---|
| `Infer<S>` | what `decode()` returns | `decode`, `decodeFromHex` |
| `InferInput<S>` | what `encode()` accepts | `encode`, `encodeToHex`, `encodeToRawBytes` |
| `InferMetadata<S>` | the `DecodedNode` tree | `decodeWithMetadata`, `decodeFromHexWithMetadata` |

They can also be used directly to name a type:

```typescript
import { defineSchema } from 'asn1-per-ts';
import type { Infer } from 'asn1-per-ts';

const TicketSchema = defineSchema({
  type: 'SEQUENCE',
  fields: [{ name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } }],
});

type Ticket = Infer<typeof TicketSchema>; // { id: number }
```

`defineSchema` is an identity function whose only job is to pin the literal
types. `as const` works too, but it also makes the object deeply readonly.

## Type mapping

| Schema node | Decoded type |
|---|---|
| `BOOLEAN` | `boolean` |
| `NULL` | `null` |
| `INTEGER` | `number` |
| `ENUMERATED` | union of `values` and `extensionValues` |
| `BIT STRING` | `BitStringValue` (`{ data: Uint8Array; bitLength: number }`) |
| `OCTET STRING` | `Uint8Array` |
| `OBJECT IDENTIFIER` | `string` |
| `IA5String` / `VisibleString` / `UTF8String` | `string` |
| `SEQUENCE` | object with one property per field |
| `SEQUENCE OF` | array of the item type |
| `CHOICE` | discriminated union `{ key: 'name'; value: T }` |
| `$ref` | the referenced schema, resolved through the registry |

Value and size constraints (`min`, `max`, `minSize`, `fixedSize`, …) are
enforced at runtime by the codecs, not in the type — TypeScript has no integer
range types. Only `ENUMERATED` narrows to a literal union.

## SEQUENCE: which properties are optional

`OPTIONAL`, `DEFAULT` and extension fields are not all optional in the same
direction, because the encoder and the decoder treat them differently:

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
    { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
  ],
  extensionFields: [{ name: 'note', schema: { type: 'UTF8String' } }],
});
```

| Field | `encode()` input | `decode()` output |
|---|---|---|
| `id` (mandatory) | required | required |
| `nickname` (`OPTIONAL`) | optional | optional — absent when not encoded |
| `version` (`DEFAULT 1`) | optional — omit to use the default | **required** — `decode()` fills in `1` |
| `note` (extension) | optional | optional — absent when the peer omits it |

So a DEFAULT field can be omitted when encoding and never has to be
null-checked after decoding:

```typescript
const decoded = codec.decode(codec.encode({ id: 5 }));
const version: number = decoded.version; // 1, no narrowing needed
```

## CHOICE: a discriminated union

A CHOICE decodes to `{ key, value }`, and the inferred type pairs each key with
its own value type, so narrowing on `key` narrows `value`:

```typescript
const codec = new SchemaCodec({
  type: 'CHOICE',
  alternatives: [
    { name: 'text', schema: { type: 'UTF8String' } },
    { name: 'data', schema: { type: 'OCTET STRING' } },
  ],
});

const decoded = codec.decodeFromHex(hex);
//    ^? { key: 'text'; value: string } | { key: 'data'; value: Uint8Array }

if (decoded.key === 'text') {
  decoded.value.toUpperCase(); // value is string here
}
```

Extension alternatives are added to the same union.

## `$ref` and registries

A single `SchemaCodec` cannot resolve `$ref` — there is nothing to resolve it
against. Use `createCodecs` to build a codec per named type; `$ref` is then
resolved both at runtime and in the inferred types:

```typescript
import { createCodecs } from 'asn1-per-ts';

const codecs = createCodecs({
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

const person = codecs.Person.decodeFromHex(hex);
//    ^? { name: string; pet?: { legs: number } }
```

`SchemaBuilder.buildAll` does the same for low-level `Codec` objects.

Recursive types are expanded up to `DefaultRefDepth` (12) levels and then
become `unknown`, which keeps the compiler from looping forever:

```typescript
type Tree = Infer<(typeof registry)['Tree'], typeof registry>;
// { value: number; children: { value: number; children: /* … 12 deep … */ unknown[] }[] }
```

Pass a smaller budget as the third type argument when a schema is deep enough
to slow the compiler down: `Infer<S, R, 4>`.

## Metadata trees are typed too

```typescript
const tree = codec.decodeWithMetadata(bytes);
tree.value.id.value;          // number
tree.value.id.meta.bitLength; // number
tree.value.nickname.value;    // string | undefined — absent OPTIONAL fields keep a node

stripMetadata(tree);
//    ^? { id: number; nickname?: string } — the same type as decode()
```

Every field of a SEQUENCE is present in the metadata tree, including OPTIONAL
fields that were not encoded; those nodes carry `value: undefined` and
`meta.present === false`. `stripMetadata` drops them again, so its return type
matches `decode()`.

## Pre-encoded `RawBytes`

Any node may be given as a `RawBytes` instead of a value, and the encoder
writes those bits verbatim. `InferInput` reflects that, so this still
type-checks:

```typescript
const inner = new SchemaCodec({ type: 'UTF8String' });

codec.encodeToHex({
  key: 'text',
  value: inner.encodeToRawBytes('hello'),
});
```

## Schemas that are only known at runtime

When the schema is loaded from JSON or produced by the ASN.1 parser, its type
is the wide `SchemaNode` union and there is nothing for TypeScript to read. The
API then behaves exactly as it did before this feature existed:

```typescript
import { parseAsn1Module, convertModuleToSchemaNodes, SchemaCodec } from 'asn1-per-ts';

const schemas = convertModuleToSchemaNodes(parseAsn1Module(asnText));
const codec = new SchemaCodec(schemas.Ticket);

const decoded = codec.decode(bytes); // unknown
```

Two ways to get types back:

1. **Declare the schema in TypeScript.** Paste the generated `SchemaNode` JSON
   into a `.ts` file wrapped in `defineSchema(...)`, and the types follow.

2. **State the type yourself.** Write the interface by hand and assert it:

   ```typescript
   interface Ticket { id: number; active: boolean }
   const decoded = codec.decode(bytes) as Ticket;
   ```

   `SchemaBuilder.fromJSON<Ticket>(json)` does the same for the low-level API.

## Common pitfalls

**A schema stored in a variable without `defineSchema`.** A plain `const`
declaration widens `'INTEGER'` to `string`, and the schema no longer matches
`SchemaNode`:

```typescript
const schema = { type: 'SEQUENCE', fields: [/* … */] }; // type: string 👎
const good = defineSchema({ type: 'SEQUENCE', fields: [/* … */] }); // 👍
```

**A value stored in a variable before encoding.** The same widening applies to
the value, which then fails to match an ENUMERATED or CHOICE literal:

```typescript
const value = { status: 'approved' };  // status: string 👎
codec.encode(value);

const typed: Infer<typeof schema> = { status: 'approved' }; // 👍
codec.encode(typed);
```

Annotating with `Infer<typeof schema>` (or adding `as const`) fixes it, and
gives you autocomplete on the way in.

**Annotating a schema as `SchemaNode`.** `const schema: SchemaNode = { … }`
throws away the literal types on purpose. Drop the annotation and let
`defineSchema` do the checking instead — it enforces the same constraint.
