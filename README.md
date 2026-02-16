# asn1-per-ts

TypeScript library for encoding and decoding data using ASN.1 PER (Packed Encoding Rules) unaligned variant (ITU-T X.691).

## Features

- **Bit-level buffer** with MSB-first encoding and automatic growth
- **Primitive codecs**: BOOLEAN, INTEGER, ENUMERATED, BIT STRING, OCTET STRING, IA5String, VisibleString, UTF8String, NULL
- **Composite codecs**: CHOICE, SEQUENCE, SEQUENCE OF
- **Constraint support**: value ranges, size constraints, extensibility markers, default values
- **Schema-driven encoding**: define types as JSON, encode/decode plain objects
- **Metadata decoding**: `decodeWithMetadata` returns a tree of `DecodedNode` objects with bit positions, raw bytes, and codec references for every field

## Install

```bash
npm install asn1-per-ts
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

### Decoding with Metadata

`decodeWithMetadata` returns a `DecodedNode` tree with full encoding metadata (bit offsets, bit lengths, raw bytes, codec references) for every field. Use `stripMetadata` to convert back to a plain object identical to `decode()`.

```typescript
import { SchemaCodec, stripMetadata } from 'asn1-per-ts';
import type { DecodedNode } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
  ],
});

const hex = codec.encodeToHex({ id: 42, active: true });
const node = codec.decodeFromHexWithMetadata(hex);

// Access field metadata
const fields = node.value as Record<string, DecodedNode>;
console.log(fields.id.value);           // 42
console.log(fields.id.meta.bitOffset);  // 0
console.log(fields.id.meta.bitLength);  // 8
console.log(fields.id.meta.rawBytes);   // Uint8Array([0x2a])

// Strip metadata to get plain object
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
| `IA5String` | ASCII strings with optional alphabet constraints |
| `VisibleString` | Printable strings with optional alphabet constraints |
| `UTF8String` | UTF-8 encoded strings |
| `NULL` | Zero-bit placeholder |
| `CHOICE` | Tagged union of alternatives |
| `SEQUENCE` | Ordered fields with OPTIONAL/DEFAULT support |
| `SEQUENCE OF` | Homogeneous list with size constraints |

## Examples

The [`examples/`](./examples/) directory contains detailed usage guides with code samples:

- **[Schema Parser](./examples/schema-parser.md)** - Parse ASN.1 text notation into `SchemaNode` definitions, constraint options, extension markers, CLI usage
- **[Encoding](./examples/encoding.md)** - Encode JavaScript objects to PER unaligned binary using `SchemaCodec` or low-level codecs
- **[Decoding](./examples/decoding.md)** - Decode PER unaligned binary data back into objects

## Sister Project

[**dosipas-ts**](https://github.com/sysdevrun/dosipas-ts) — a TypeScript library built on top of asn1-per-ts for encoding and decoding DOSIPAS / ERA electronic ticket data.

## Development

```bash
npm test          # Run tests
npm run build     # Build library
```

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
