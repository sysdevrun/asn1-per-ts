# Schema Parser

Parse ASN.1 text notation into `SchemaNode` JSON definitions that can be used for PER unaligned encoding and decoding.

## Overview

The schema parser converts ASN.1 module text (`.asn` files) into a `Record<string, SchemaNode>` map, where each top-level type assignment becomes an entry. The pipeline has two steps:

1. **Parse** the ASN.1 text into an AST using `parseAsn1Module()` (`src/parser/AsnParser.ts`)
2. **Convert** the AST into `SchemaNode` objects using `convertModuleToSchemaNodes()` (`src/parser/toSchemaNode.ts`)

The resulting `SchemaNode` objects can be used directly with `SchemaCodec` (`src/schema/SchemaCodec.ts`) or `SchemaBuilder` (`src/schema/SchemaBuilder.ts`) for encoding and decoding.

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
const decoded = codec.decodeFromHex(hex);
// decoded === { id: 42, status: 'approved' }
```

### Schemas with `$ref` (recursive or cross-referenced types)

When a module contains type references that create cycles (e.g., a tree structure), the converter emits `$ref` nodes. Use `SchemaBuilder.buildAll()` instead of `SchemaCodec` to resolve them:

```typescript
import {
  parseAsn1Module,
  convertModuleToSchemaNodes,
  SchemaBuilder,
  BitBuffer,
} from 'asn1-per-ts';

const asn1Text = `
TreeModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  Tree ::= SEQUENCE {
    value    INTEGER (0..255),
    children SEQUENCE OF Tree
  }
END
`;

const schemas = convertModuleToSchemaNodes(parseAsn1Module(asn1Text));
// schemas.Tree contains $ref nodes for the recursive reference

// buildAll() resolves $ref lazily
const codecs = SchemaBuilder.buildAll(schemas);

const buffer = BitBuffer.alloc();
codecs.Tree.encode(buffer, {
  value: 1,
  children: [
    { value: 2, children: [] },
    { value: 3, children: [{ value: 4, children: [] }] },
  ],
});
```

## CLI Usage

The `cli/generate-schema.ts` tool converts an `.asn` file to a `.schema.json` file from the command line:

```bash
# Print schema JSON to stdout
npx tsx cli/generate-schema.ts input.asn

# Write schema JSON to a file
npx tsx cli/generate-schema.ts input.asn output.schema.json
```

The tool reads the ASN.1 file, parses it, converts all type assignments, and outputs a single JSON object mapping type names to `SchemaNode` definitions. See `cli/generate-schema.ts` for the implementation.

## Supported ASN.1 Types

The parser (`src/parser/grammar.ts`, `src/parser/types.ts`) supports the following ASN.1 types:

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

- `extensionFields: []` (present but empty) marks the SEQUENCE as extensible with no additions.
- `extensionFields: [...]` (non-empty) marks it as extensible with extension additions.
- Omitting `extensionFields` entirely means the type is **not** extensible.
- The same pattern applies to `extensionValues` (ENUMERATED) and `extensionAlternatives` (CHOICE).

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

## Building SchemaNode Manually (Without Parser)

You can construct `SchemaNode` objects directly in TypeScript without using the ASN.1 parser. This is useful for simple schemas or when you want full control:

```typescript
import { SchemaCodec, type SchemaNode } from 'asn1-per-ts';

const schema: SchemaNode = {
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
    {
      name: 'status',
      schema: { type: 'ENUMERATED', values: ['pending', 'approved', 'rejected'] },
    },
  ],
};

const codec = new SchemaCodec(schema);
```

See `src/schema/SchemaBuilder.ts` for the full `SchemaNode` type definition.

## Pre-generated Schemas

The `schemas/uic-barcode/` directory contains pre-generated `SchemaNode` JSON files from real-world ASN.1 specifications (UIC barcode headers, rail ticket data, Intercode 6). These can be loaded and used directly:

```typescript
import headerSchemas from './schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';
import { SchemaCodec, type SchemaNode } from 'asn1-per-ts';

const codec = new SchemaCodec(headerSchemas.UicBarcodeHeader as unknown as SchemaNode);
```

## Related Files

| File | Description |
|---|---|
| `src/parser/AsnParser.ts` | `parseAsn1Module()` - parses ASN.1 text into AST |
| `src/parser/toSchemaNode.ts` | `convertModuleToSchemaNodes()` - converts AST to SchemaNode map |
| `src/parser/grammar.ts` | PEG grammar for ASN.1 notation subset |
| `src/parser/types.ts` | TypeScript types for ASN.1 AST (`AsnModule`, `AsnType`, etc.) |
| `src/schema/SchemaBuilder.ts` | `SchemaBuilder.build()` / `buildAll()` - builds codecs from SchemaNode |
| `src/schema/SchemaCodec.ts` | `SchemaCodec` - high-level encode/decode with hex helpers |
| `cli/generate-schema.ts` | CLI tool to convert `.asn` files to `.schema.json` |
| `schemas/uic-barcode/` | Pre-generated SchemaNode JSON files |
