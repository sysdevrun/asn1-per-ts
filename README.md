# asn1-per-ts

[![npm](https://img.shields.io/npm/v/asn1-per-ts)](https://www.npmjs.com/package/asn1-per-ts)

**[Try it in the sandbox](https://sysdevrun.github.io/asn1-per-ts/)**

TypeScript library for encoding and decoding data using ASN.1 PER (Packed Encoding Rules) unaligned variant (ITU-T X.691).

## Features

- **Bit-level buffer** with MSB-first encoding and automatic growth
- **Primitive codecs**: BOOLEAN, INTEGER, ENUMERATED, BIT STRING, OCTET STRING, OBJECT IDENTIFIER, IA5String, VisibleString, UTF8String, NULL
- **Composite codecs**: CHOICE, SEQUENCE, SEQUENCE OF
- **Constraint support**: value ranges, size constraints, extensibility markers, default values
- **Schema-driven encoding**: define types as JSON, encode/decode plain objects
- **Typed from the schema**: `decode()` returns the type the schema describes and `encode()` rejects values that do not fit — at compile time, with no runtime validation and no extra dependency
- **Three ways to say it**: an inline `SchemaNode`, the `asn` builder DSL, or TypeScript generated from a `.asn` file — all sharing one interchange format and one codec interface
- **Metadata decoding**: `decodeWithMetadata` returns a tree of `DecodedNode` objects with bit positions, raw bytes, and codec references for every field
- **Pre-encoded passthrough**: embed already-encoded bits verbatim with `RawBytes`, via `codec.raw`

## Install

```bash
npm install asn1-per-ts
```

The package also installs an `asn1-per-ts` command:

```bash
npx asn1-per-ts types  ticket.asn src/generated/ticket.ts  # TypeScript types + codecs
npx asn1-per-ts schema ticket.asn ticket.schema.json       # SchemaNode JSON
```

## Usage

### Low-level codec API

```typescript
import { BitBuffer, IntegerCodec, BooleanCodec, SequenceCodec } from 'asn1-per-ts';

// Constrained integer (0..255) uses 8 bits
const intCodec = new IntegerCodec({ min: 0, max: 255 });

const buf = BitBuffer.alloc();
intCodec.encode(buf, 42);
buf.reset();
console.log(intCodec.decode(buf)); // 42
```

### Schema-driven API

```typescript
import { SchemaCodec } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
    { name: 'status', schema: { type: 'ENUMERATED', values: ['pending', 'approved', 'rejected'] } },
  ],
});

const hex = codec.encodeToHex({ id: 42, active: true, status: 'approved' });
console.log(hex);

const decoded = codec.decodeFromHex(hex);
console.log(decoded);
```

### Types come from the schema

The schema is read as a literal type, so the decoded type is derived from it —
no interface to write, no cast to make:

```typescript
const decoded = codec.decodeFromHex(hex);
//    ^? { id: number; active: boolean; status: 'pending' | 'approved' | 'rejected' }

decoded.status; // 'pending' | 'approved' | 'rejected'

codec.encodeToHex({ id: 42, active: true, status: 'unknown' });
//                                                ~~~~~~~~~ not one of the ENUMERATED values
```

OPTIONAL fields become optional properties, DEFAULT fields are always present
after decoding, CHOICE becomes a discriminated union, and `$ref` resolves
through `createCodecs`. When the schema is only known at runtime (parsed from
JSON or from ASN.1 text), everything degrades to `unknown` exactly as before.

### Three front-ends, one interchange format

`SchemaNode` is the interchange format; the three ways of describing a type all
produce it and all hand back the same `TypedCodec`.

```typescript
import { SchemaCodec, asn } from 'asn1-per-ts';

// 1. inline SchemaNode — the schema is data, types are read from the literal
const fromLiteral = new SchemaCodec({ type: 'SEQUENCE', fields: [/* … */] });

// 2. the asn DSL — types ride in the value, no widening traps, short errors
const fromDsl = asn.codec(
  asn.sequence({
    id: asn.integer({ min: 0, max: 255 }),
    status: asn.enumerated(['pending', 'approved']),
    nickname: asn.ia5String().optional(),
  }),
);

// 3. generated from ASN.1 — named types, cheapest to compile, best errors
//    npx asn1-per-ts types ticket.asn src/generated/ticket.ts
import { codecs } from './generated/ticket.js';
```

Pick by where the schema comes from: generate from `.asn` files, use the DSL for
hand-written schemas, use `SchemaNode` when the schema itself is data.

- [examples/typed-api.md](examples/typed-api.md) — inline schemas and the `Infer` types
- [examples/dsl.md](examples/dsl.md) — the `asn` builder DSL
- [examples/codegen.md](examples/codegen.md) — generating TypeScript from ASN.1

### Decoding with Metadata

`decodeWithMetadata` returns a `DecodedNode` tree with full encoding metadata (bit offsets, bit lengths, raw bytes, codec references) for every field. Use `stripMetadata` to convert back to a plain object identical to `decode()`.

```typescript
import { SchemaCodec, stripMetadata } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
  ],
});

const hex = codec.encodeToHex({ id: 42, active: true });
const node = codec.decodeFromHexWithMetadata(hex);

// The tree is typed from the schema — no cast needed
console.log(node.value.id.value);           // 42 (number)
console.log(node.value.id.meta.bitOffset);  // 0
console.log(node.value.id.meta.bitLength);  // 8
console.log(node.value.id.meta.rawBytes);   // Uint8Array([0x2a])

// Strip metadata to get the plain object, with the same type as decode()
const plain = stripMetadata(node);
// plain === { id: 42, active: true }
```

### Extension Markers

Extension markers (`...`) indicate that a type may be extended in future versions, providing forward compatibility. When present, PER encoding includes a 1-bit extension marker prefix (0 = not extended, 1 = extended).

#### In ASN.1 notation

Use `...` to mark a type as extensible in ASN.1 schema text parsed by the built-in parser:

```asn1
-- SEQUENCE: extension marker separates root fields from extension additions
MessageV1 ::= SEQUENCE {
    id     INTEGER (0..255),
    name   IA5String,
    ...                        -- extensible, no extensions yet
}

MessageV2 ::= SEQUENCE {
    id     INTEGER (0..255),
    name   IA5String,
    ...,                       -- extension marker
    email  IA5String           -- extension addition
}

-- ENUMERATED: extension marker separates root values from extension values
Color ::= ENUMERATED { red, green, blue, ... }
ColorV2 ::= ENUMERATED { red, green, blue, ..., yellow, purple }

-- CHOICE: extension marker separates root alternatives from extension alternatives
Shape ::= CHOICE { circle BOOLEAN, ..., polygon INTEGER }

-- Constraints: extensible constraints allow values outside the root range
FlexInt ::= INTEGER (0..100, ...)
FlexStr ::= OCTET STRING (SIZE (1..50, ...))
```

#### In JSON SchemaNode definitions

When building schemas directly as JSON `SchemaNode` objects, indicate extensibility with these properties:

```typescript
// SEQUENCE: provide extensionFields (even empty [] to mark as extensible)
const schema: SchemaNode = {
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
  extensionFields: [],  // extensible with no additions yet
};

// ENUMERATED: provide extensionValues
{ type: 'ENUMERATED', values: ['red', 'green'], extensionValues: [] }

// CHOICE: provide extensionAlternatives
{ type: 'CHOICE', alternatives: [...], extensionAlternatives: [] }

// Constrained types: set extensible: true
{ type: 'INTEGER', min: 0, max: 100, extensible: true }
{ type: 'BIT STRING', minSize: 1, maxSize: 50, extensible: true }
```

Key distinction: providing an empty array (`extensionFields: []`) marks the type as extensible, while omitting the property entirely (`extensionFields: undefined`) means the type is not extensible. This matters because extensible types include the 1-bit extension marker in the encoding.

## Supported Types

| Type | Description |
|------|-------------|
| `BOOLEAN` | Single bit |
| `INTEGER` | Constrained, semi-constrained, or unconstrained |
| `ENUMERATED` | Indexed enumeration with optional extensions |
| `BIT STRING` | Bit sequences with size constraints |
| `OCTET STRING` | Byte sequences with size constraints |
| `OBJECT IDENTIFIER` | Dot-notation OIDs |
| `IA5String` | ASCII strings with optional alphabet constraints |
| `VisibleString` | Printable strings with optional alphabet constraints |
| `UTF8String` | UTF-8 encoded strings |
| `NULL` | Zero-bit placeholder |
| `CHOICE` | Tagged union of alternatives |
| `SEQUENCE` | Ordered fields with OPTIONAL/DEFAULT support |
| `SEQUENCE OF` | Homogeneous list with size constraints |

## Examples

The [`examples/`](./examples/) directory contains detailed usage guides with code samples:

- **[Typed API](./examples/typed-api.md)** - Types inferred from an inline schema: `Infer`, `InferInput`, `InferMetadata`, `$ref` registries
- **[Builder DSL](./examples/dsl.md)** - The `asn` DSL, where types ride in the value instead of being read from literals
- **[Code generation](./examples/codegen.md)** - Generating TypeScript types and codecs from a `.asn` file
- **[Schema Parser](./examples/schema-parser.md)** - Parse ASN.1 text notation into `SchemaNode` definitions, constraint options, extension markers, CLI usage
- **[Encoding](./examples/encoding.md)** - Encode JavaScript objects to PER unaligned binary using `SchemaCodec` or low-level codecs
- **[Decoding](./examples/decoding.md)** - Decode PER unaligned binary data back into objects

## Sister Project

[**dosipas-ts**](https://github.com/sysdevrun/dosipas-ts) — a TypeScript library built on top of asn1-per-ts for encoding and decoding DOSIPAS / ERA electronic ticket data.

## Development

```bash
npm test             # Run tests
npm run build        # Build library to dist/
npx tsc --noEmit     # Type-check without emitting

# Run the CLI from source, without building
npx tsx src/cli/main.ts types <in.asn> [out.ts]
```

Changes are recorded in [CHANGELOG.md](./CHANGELOG.md); releasing is described in
[PUBLISH.md](./PUBLISH.md).

## Website

The `website/` directory contains a React + TailwindCSS demo app for interactive ASN.1 PER encoding and decoding.

```bash
cd website
npm install
npm run build     # Build for GitHub Pages (uses ./ asset path)
npm run dev       # Development server
```

## License

MIT
