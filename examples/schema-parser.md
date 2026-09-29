# Schema Parser

Parse ASN.1 text notation into `SchemaNode` definitions that can be used for PER
unaligned encoding and decoding.

## Which path do you want?

`SchemaNode` is the interchange format, and there are two ways to get from a
`.asn` file to working codecs:

| | What you get | When |
|---|---|---|
| **Parse at runtime** (this guide) | `SchemaNode` objects and codecs whose `decode()` returns `unknown` | the schema is chosen at runtime, comes over the wire, or is edited by a user |
| **[Generate TypeScript](./codegen.md)** | named interfaces and typed codecs, ahead of time | the `.asn` file is known when you build |

A schema parsed at runtime is just data as far as the compiler is concerned, so
nothing can be inferred from it — `decode()` returns `unknown` and `encode()`
accepts `unknown`, exactly as this library behaved before typed schemas existed.
If your `.asn` file is checked in, prefer `asn1-per-ts types` and get real types.

## Overview

The parser converts ASN.1 module text into a `Record<string, SchemaNode>` map,
where each top-level type assignment becomes an entry. The pipeline has two
steps:

1. **Parse** the ASN.1 text into an AST using `parseAsn1Module()` (`src/parser/AsnParser.ts`)
2. **Convert** the AST into `SchemaNode` objects using `convertModuleToSchemaNodes()` (`src/parser/toSchemaNode.ts`)

The resulting `SchemaNode` objects work with `SchemaCodec`, `createCodecs`, or
`SchemaBuilder` for encoding and decoding, and with `generateTypeScript` for
code generation.

## Programmatic Usage

### Basic: Parse and convert an ASN.1 module

```typescript
import { parseAsn1Module, convertModuleToSchemaNodes } from 'asn1-per-ts';

const asn1Text = `
MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  PersonRecord ::= SEQUENCE {
    name   IA5String (SIZE (1..50)),
    age    INTEGER (0..150),
    active BOOLEAN
  }
END
`;

// Step 1: Parse ASN.1 text into AST
const module = parseAsn1Module(asn1Text);
// module.name === 'MyModule'
// module.assignments is an array of AsnTypeAssignment objects

// Step 2: Convert AST to SchemaNode map
const schemas = convertModuleToSchemaNodes(module);
// schemas.PersonRecord is a SchemaNode of type 'SEQUENCE'

console.log(JSON.stringify(schemas, null, 2));
```

Output:

```json
{
  "PersonRecord": {
    "type": "SEQUENCE",
    "fields": [
      { "name": "name", "schema": { "type": "IA5String", "minSize": 1, "maxSize": 50 } },
      { "name": "age", "schema": { "type": "INTEGER", "min": 0, "max": 150 } },
      { "name": "active", "schema": { "type": "BOOLEAN" } }
    ]
  }
}
```

### Using the parsed schema for encoding/decoding

```typescript
import {
  parseAsn1Module,
  convertModuleToSchemaNodes,
  SchemaCodec,
} from 'asn1-per-ts';

const asn1Text = `
Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  Status ::= ENUMERATED { pending, approved, rejected }
  Request ::= SEQUENCE {
    id     INTEGER (0..65535),
    status Status
  }
END
`;

const schemas = convertModuleToSchemaNodes(parseAsn1Module(asn1Text));

const codec = new SchemaCodec(schemas.Request);
const hex = codec.encodeToHex({ id: 42, status: 'approved' });
// hex === '002a40'

const decoded = codec.decodeFromHex(hex);
// at runtime: { id: 42, status: 'approved' }
// to TypeScript: unknown
```

The value is right, but its type is `unknown`, because `schemas.Request` is the
wide `SchemaNode` union and there is no literal for the compiler to read. Three
ways to get a type back, in order of preference:

1. **Generate ahead of time** with [`asn1-per-ts types`](./codegen.md). Best
   option whenever the `.asn` file is checked in.
2. **Declare the schema in TypeScript** instead of parsing it — with
   [`defineSchema`](./typed-api.md) or the [`asn` DSL](./dsl.md).
3. **Assert the type** when you genuinely cannot know the schema until runtime:

   ```typescript
   interface Request { id: number; status: 'pending' | 'approved' | 'rejected' }
   const decoded = codec.decode(bytes) as Request;
   ```

### Type references are inlined

The converter resolves a reference to another type by **expanding it in place**.
In the module above, `Status` appears both as its own entry and inlined inside
`Request`:

```json
{
  "type": "SEQUENCE",
  "fields": [
    { "name": "id", "schema": { "type": "INTEGER", "min": 0, "max": 65535 } },
    {
      "name": "status",
      "schema": { "type": "ENUMERATED", "values": ["pending", "approved", "rejected"] }
    }
  ]
}
```

There is no `$ref` here. That matters in two ways:

- A module where many types share a common structure produces a `SchemaNode`
  registry considerably larger than the ASN.1 it came from.
- The code generator matches those inlined structures back to the types they came
  from, so generated TypeScript references `Status` rather than repeating it. See
  [codegen.md](./codegen.md#named-types-not-inlined-structures).

### Recursive types and `$ref`

Inlining cannot expand a cycle, so a type that reaches itself emits a `$ref`
node instead — and only then:

```typescript
const asn1Text = `
TreeModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  Tree ::= SEQUENCE {
    value    INTEGER (0..255),
    children SEQUENCE OF Tree
  }
END
`;

const schemas = convertModuleToSchemaNodes(parseAsn1Module(asn1Text));
```

```json
{
  "type": "SEQUENCE",
  "fields": [
    { "name": "value", "schema": { "type": "INTEGER", "min": 0, "max": 255 } },
    {
      "name": "children",
      "schema": { "type": "SEQUENCE OF", "item": { "type": "$ref", "ref": "Tree" } }
    }
  ]
}
```

A `$ref` needs a registry to resolve against, so build the whole module at once.
`new SchemaCodec(schemas.Tree)` throws — it has nothing to resolve `$ref`
against.

```typescript
import { createCodecs } from 'asn1-per-ts';

const codecs = createCodecs(schemas);

const hex = codecs.Tree.encodeToHex({
  value: 1,
  children: [
    { value: 2, children: [] },
    { value: 3, children: [{ value: 4, children: [] }] },
  ],
});
```

`createCodecs` resolves `$ref` lazily and returns a `SchemaCodec` per type, with
the hex and metadata helpers. `SchemaBuilder.buildAll(schemas)` does the same at
the lower level, returning bare `Codec` objects that encode into a `BitBuffer`
you supply.

## CLI Usage

The `asn1-per-ts` binary converts an `.asn` file to a `.schema.json` file from
the command line:

```bash
# Print schema JSON to stdout
npx asn1-per-ts schema input.asn

# Write schema JSON to a file
npx asn1-per-ts schema input.asn output.schema.json
```

The tool reads the ASN.1 file, parses it, converts all type assignments, and
outputs a single JSON object mapping type names to `SchemaNode` definitions. With
no output path it writes to stdout, so it pipes. Progress messages go to stderr.

The sibling `types` subcommand emits TypeScript instead of JSON — see
[codegen.md](./codegen.md). Both accept the same input; `types` also accepts a
`.schema.json` produced by `schema`, so you can keep the JSON as a build artifact
and generate from it.

## Supported ASN.1 Types

The parser (`src/parser/grammar.ts`, `src/parser/types.ts`) supports the
following ASN.1 types:

| ASN.1 Type | SchemaNode `type` | Notes |
|---|---|---|
| `BOOLEAN` | `BOOLEAN` | |
| `NULL` | `NULL` | |
| `INTEGER` | `INTEGER` | With optional value constraint `(min..max)` |
| `ENUMERATED` | `ENUMERATED` | Root values and optional extension values |
| `BIT STRING` | `BIT STRING` | With optional `SIZE` constraint |
| `OCTET STRING` | `OCTET STRING` | With optional `SIZE` constraint |
| `IA5String` | `IA5String` | With optional `SIZE` constraint |
| `VisibleString` | `VisibleString` | With optional `SIZE` constraint |
| `UTF8String` | `UTF8String` | With optional `SIZE` constraint |
| `OBJECT IDENTIFIER` | `OBJECT IDENTIFIER` | OID dot-notation strings |
| `SEQUENCE` | `SEQUENCE` | Fields with `OPTIONAL` / `DEFAULT` support |
| `SEQUENCE OF` | `SEQUENCE OF` | With optional `SIZE` constraint |
| `CHOICE` | `CHOICE` | Tagged union of alternatives |

This is a practical subset, not all of ASN.1. `SET`, `REAL`, the date/time types,
`IMPORTS`, parameterized types and several constraint forms are not implemented —
[TODO.md](../TODO.md) is the current list. The parser throws on notation it does
not recognise rather than guessing.

## Constraint Options

### Value constraints (INTEGER)

```asn1
SmallInt ::= INTEGER (0..255)          -- fixed range
FlexInt  ::= INTEGER (0..100, ...)     -- extensible range
```

Produces `SchemaNode`:

```json
{ "type": "INTEGER", "min": 0, "max": 255 }
{ "type": "INTEGER", "min": 0, "max": 100, "extensible": true }
```

- `min` / `max` define the constrained range. PER encoding uses the minimum number of bits for the range.
- `extensible: true` adds a 1-bit extension marker prefix. Values inside the root range use compact encoding; values outside use unconstrained encoding.

Constraints are enforced at runtime by the codecs, in every front-end. They do
not appear in the TypeScript types — an `INTEGER (0..255)` is a `number`, because
TypeScript has no integer range types.

### Size constraints (strings, BIT STRING, OCTET STRING, SEQUENCE OF)

```asn1
Name    ::= IA5String (SIZE (1..50))
FixedId ::= OCTET STRING (SIZE (4))
FlexBuf ::= BIT STRING (SIZE (8..256, ...))
```

Produces `SchemaNode`:

```json
{ "type": "IA5String", "minSize": 1, "maxSize": 50 }
{ "type": "OCTET STRING", "fixedSize": 4 }
{ "type": "BIT STRING", "minSize": 8, "maxSize": 256, "extensible": true }
```

- When `min === max`, the converter uses `fixedSize` (no length determinant encoded).
- Otherwise `minSize` / `maxSize` are used.
- `extensible: true` adds a 1-bit extension marker for the size constraint.

### Extension markers

Extension markers (`...`) indicate that a type may be extended in future versions. They affect encoding by adding a 1-bit prefix.

```asn1
-- SEQUENCE with extension marker
MessageV1 ::= SEQUENCE {
    id   INTEGER (0..255),
    ...
}

-- SEQUENCE with extension additions
MessageV2 ::= SEQUENCE {
    id    INTEGER (0..255),
    ...,
    email IA5String
}

-- ENUMERATED with extensions
Color ::= ENUMERATED { red, green, blue, ..., yellow }

-- CHOICE with extensions
Shape ::= CHOICE { circle BOOLEAN, ..., polygon INTEGER }
```

Produces `SchemaNode`:

```json
{
  "type": "SEQUENCE",
  "fields": [{ "name": "id", "schema": { "type": "INTEGER", "min": 0, "max": 255 } }],
  "extensionFields": []
}
```

```json
{ "type": "ENUMERATED", "values": ["red", "green", "blue"], "extensionValues": ["yellow"] }
```

- `extensionFields: []` (present but empty) marks the SEQUENCE as extensible with no additions.
- `extensionFields: [...]` (non-empty) marks it as extensible with extension additions.
- Omitting `extensionFields` entirely means the type is **not** extensible.
- The same pattern applies to `extensionValues` (ENUMERATED) and `extensionAlternatives` (CHOICE).

Extension additions decode as optional: a peer that does not send them leaves
those fields absent.

### OPTIONAL and DEFAULT fields

```asn1
Record ::= SEQUENCE {
    required  INTEGER (0..255),
    nickname  IA5String OPTIONAL,
    version   INTEGER (0..10) DEFAULT 1
}
```

Produces `SchemaNode`:

```json
{
  "type": "SEQUENCE",
  "fields": [
    { "name": "required", "schema": { "type": "INTEGER", "min": 0, "max": 255 } },
    { "name": "nickname", "schema": { "type": "IA5String" }, "optional": true },
    { "name": "version", "schema": { "type": "INTEGER", "min": 0, "max": 10 }, "defaultValue": 1 }
  ]
}
```

- `optional: true` fields are preceded by a 1-bit presence flag in the encoding.
- `defaultValue` fields also use a presence flag; when absent, the default is used on decode.

The two are not symmetric once types are involved: an OPTIONAL field is optional
both to encode and after decoding, while a DEFAULT field may be omitted when
encoding but is always present after decoding, because the decoder substitutes
the default.

## Writing schemas without the parser

A `SchemaNode` written in TypeScript rather than parsed *does* carry types, since
the compiler can read the literal:

```typescript
import { SchemaCodec } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'status', schema: { type: 'ENUMERATED', values: ['pending', 'approved'] } },
  ],
});

const decoded = codec.decodeFromHex(hex);
//    ^? { id: number; status: 'pending' | 'approved' }
```

Note the missing `: SchemaNode` annotation — adding one throws the literal types
away and takes you back to `unknown`. [typed-api.md](./typed-api.md) covers that
and the rest of the inline-schema API; [dsl.md](./dsl.md) covers the `asn`
builder, which avoids the annotation trap entirely.

The full `SchemaNode` union is defined in `src/schema/SchemaNode.ts`.

## Related Files

| File | Description |
|---|---|
| `src/parser/AsnParser.ts` | `parseAsn1Module()` - parses ASN.1 text into AST |
| `src/parser/toSchemaNode.ts` | `convertModuleToSchemaNodes()` - converts AST to SchemaNode map |
| `src/parser/grammar.ts` | PEG grammar for ASN.1 notation subset |
| `src/parser/types.ts` | TypeScript types for ASN.1 AST (`AsnModule`, `AsnType`, etc.) |
| `src/schema/SchemaNode.ts` | The `SchemaNode` interchange format and `SchemaRegistry` |
| `src/schema/SchemaBuilder.ts` | `SchemaBuilder.build()` / `buildAll()` - builds codecs from SchemaNode |
| `src/schema/SchemaCodec.ts` | `SchemaCodec`, `createCodec`, `createCodecs` - high-level encode/decode |
| `src/codegen/generateTypeScript.ts` | `generateTypeScript()` - SchemaNode registry to TypeScript source |
| `src/cli/cli.ts` | CLI: `asn1-per-ts schema` (`.asn` to `.schema.json`) and `asn1-per-ts types` (`.asn` to TypeScript) |
