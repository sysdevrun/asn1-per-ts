# per-unaligned-ts

TypeScript library for encoding and decoding data using ASN.1 PER (Packed Encoding Rules) unaligned variant (ITU-T X.691).

## Features

- **Bit-level buffer** with MSB-first encoding and automatic growth
- **Primitive codecs**: BOOLEAN, INTEGER, ENUMERATED, BIT STRING, OCTET STRING, IA5String, VisibleString, UTF8String, NULL
- **Composite codecs**: CHOICE, SEQUENCE, SEQUENCE OF
- **Constraint support**: value ranges, size constraints, extensibility markers, default values
- **Schema-driven encoding**: define types as JSON, encode/decode plain objects

## Install

```bash
npm install per-unaligned-ts
```

## Usage

### Low-level codec API

```typescript
import { BitBuffer, IntegerCodec, BooleanCodec, SequenceCodec } from 'per-unaligned-ts';

// Constrained integer (0..255) uses 8 bits
const intCodec = new IntegerCodec({ min: 0, max: 255 });

const buf = BitBuffer.alloc();
intCodec.encode(buf, 42);
buf.reset();
console.log(intCodec.decode(buf)); // 42
```

### Schema-driven API

```typescript
import { SchemaCodec } from 'per-unaligned-ts';

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

## Development

```bash
npm test          # Run tests
npm run build     # Build library
```

## Website

The `website/` directory contains a React + TailwindCSS demo app for interactive schema-based encoding/decoding.

```bash
cd website
npm install
npm run build     # Build for GitHub Pages (uses ./ asset path)
npm run dev       # Development server
```

## License

MIT
