# Encoding Objects to Binary

Encode JavaScript/TypeScript objects into PER unaligned binary data.

## Overview

There are two levels of encoding API:

1. **High-level**: `SchemaCodec` (`src/schema/SchemaCodec.ts`) - encode a plain object to `Uint8Array` or hex string using a `SchemaNode` definition.
2. **Low-level**: Individual codec classes (`src/codecs/`) + `BitBuffer` (`src/BitBuffer.ts`) - encode directly into a bit-level buffer.

## High-Level Encoding with SchemaCodec

### Encode to hex string

```typescript
import { SchemaCodec } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
  ],
});

const hex = codec.encodeToHex({ id: 42, active: true });
// hex === '2a80'
```

`SchemaCodec.encodeToHex()` allocates a `BitBuffer`, encodes the value, and returns the hex representation. See `src/schema/SchemaCodec.ts:24`.

### Encode to Uint8Array

```typescript
const bytes = codec.encode({ id: 42, active: true });
// bytes is a Uint8Array
```

`SchemaCodec.encode()` returns the compact `Uint8Array` with trailing bits zero-padded. See `src/schema/SchemaCodec.ts:17`.

### Encode with OPTIONAL / DEFAULT fields

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
    {
      name: 'version',
      schema: { type: 'INTEGER', min: 0, max: 10 },
      defaultValue: 1,
    },
  ],
});

// All fields present
const hex1 = codec.encodeToHex({ id: 5, nickname: 'hello', version: 3 });

// Optional field absent, default field matches default → compact encoding
const hex2 = codec.encodeToHex({ id: 5 });
// nickname is omitted (presence bit = 0)
// version uses default (presence bit = 0, default value 1 used on decode)
```

When encoding:
- OPTIONAL fields that are `undefined` or missing get a presence bit of `0` (no data follows).
- DEFAULT fields that are `undefined`, missing, or equal to the default value get a presence bit of `0`.
- PER uses 1 bit per OPTIONAL/DEFAULT field in the SEQUENCE bitmap preamble.

### Encode ENUMERATED values

```typescript
const codec = new SchemaCodec({
  type: 'ENUMERATED',
  values: ['pending', 'approved', 'rejected'],
});

const hex = codec.encodeToHex('approved');
// Encodes index 1 using ceil(log2(3)) = 2 bits
```

### Encode CHOICE values

```typescript
const codec = new SchemaCodec({
  type: 'CHOICE',
  alternatives: [
    { name: 'flag', schema: { type: 'BOOLEAN' } },
    { name: 'count', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
});

// Encode the 'count' alternative
const hex = codec.encodeToHex({ count: 42 });

// Encode the 'flag' alternative
const hex2 = codec.encodeToHex({ flag: true });
```

CHOICE values are encoded as an object with a single key matching one of the alternative names. The CHOICE index is encoded first, followed by the alternative's value.

### Encode SEQUENCE OF (arrays)

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE OF',
  item: { type: 'INTEGER', min: 0, max: 255 },
  minSize: 0,
  maxSize: 10,
});

const hex = codec.encodeToHex([10, 20, 30]);
```

### Roundtrip: encode then decode

```typescript
import { SchemaCodec } from 'asn1-per-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 65535 } },
    { name: 'name', schema: { type: 'IA5String', minSize: 1, maxSize: 50 } },
    {
      name: 'role',
      schema: { type: 'ENUMERATED', values: ['admin', 'user', 'guest'] },
    },
  ],
});

const original = { id: 1234, name: 'Alice', role: 'admin' };

const hex = codec.encodeToHex(original);
const decoded = codec.decodeFromHex(hex);
// decoded deep-equals original
```

## Encoding from ASN.1 Text (Parse + Encode)

Combine the parser with encoding:

```typescript
import {
  parseAsn1Module,
  convertModuleToSchemaNodes,
  SchemaCodec,
} from 'asn1-per-ts';

const asn1Text = `
Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  Message ::= SEQUENCE {
    id    INTEGER (0..65535),
    text  IA5String (SIZE (1..100))
  }
END
`;

const schemas = convertModuleToSchemaNodes(parseAsn1Module(asn1Text));
const codec = new SchemaCodec(schemas.Message);

const hex = codec.encodeToHex({ id: 42, text: 'world' });
const decoded = codec.decodeFromHex(hex);
// decoded === { id: 42, text: 'world' }
```

## Encoding with Extension Markers

Extension markers enable forward-compatible encoding. When a type is extensible, a 1-bit prefix is added.

### Extensible SEQUENCE

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
  extensionFields: [], // extensible with no additions yet
});

// Encodes with a 0 extension bit prefix (not extended)
const hex = codec.encodeToHex({ id: 42 });
```

### Versioned encoding with extensions

```typescript
// V1 schema: extensible, no extension fields
const v1 = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
  extensionFields: [],
});

// V2 schema: adds 'name' as extension field
const v2 = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
  extensionFields: [
    { name: 'name', schema: { type: 'IA5String' } },
  ],
});

// Encode with V2
const hex = v2.encodeToHex({ id: 100, name: 'world' });

// V1 decoder can still decode (ignores unknown extensions)
const decoded = v1.decodeFromHex(hex);
// decoded === { id: 100 }
```

### Extensible INTEGER constraint

```typescript
const codec = new SchemaCodec({
  type: 'INTEGER',
  min: 0,
  max: 100,
  extensible: true,
});

// Value within range → compact encoding with 0 extension bit
const hex1 = codec.encodeToHex(50);

// Value outside range → 1 extension bit + unconstrained encoding
const hex2 = codec.encodeToHex(999);
```

## Low-Level Encoding with BitBuffer and Codecs

### BitBuffer basics

```typescript
import { BitBuffer } from 'asn1-per-ts';

// Allocate a writable buffer
const buffer = BitBuffer.alloc();

// Write individual bits
buffer.writeBit(1);
buffer.writeBit(0);

// Write multiple bits from an integer (MSB first)
buffer.writeBits(42, 8); // writes 00101010

// Write raw bytes
buffer.writeOctets(new Uint8Array([0xde, 0xad]));

// Get results
const bytes = buffer.toUint8Array(); // compact Uint8Array
const hex = buffer.toHex();          // hex string
const binary = buffer.toBinaryString(); // '0' and '1' characters
```

`BitBuffer.alloc()` creates a growable buffer that automatically expands as needed. See `src/BitBuffer.ts:18`.

### Encode a constrained INTEGER

```typescript
import { BitBuffer, IntegerCodec } from 'asn1-per-ts';

const codec = new IntegerCodec({ min: 0, max: 255 });

const buffer = BitBuffer.alloc();
codec.encode(buffer, 42);
// Uses exactly 8 bits (ceil(log2(256)))

console.log(buffer.toHex()); // '2a'
```

### Encode a BOOLEAN

```typescript
import { BitBuffer, BooleanCodec } from 'asn1-per-ts';

const codec = new BooleanCodec();

const buffer = BitBuffer.alloc();
codec.encode(buffer, true);
// Uses exactly 1 bit

console.log(buffer.toBinaryString()); // '1'
```

### Encode an ENUMERATED

```typescript
import { BitBuffer, EnumeratedCodec } from 'asn1-per-ts';

const codec = new EnumeratedCodec({
  values: ['red', 'green', 'blue'],
});

const buffer = BitBuffer.alloc();
codec.encode(buffer, 'green');
// Encodes index 1 using ceil(log2(3)) = 2 bits
```

### Encode BIT STRING and OCTET STRING

```typescript
import { BitBuffer, BitStringCodec, OctetStringCodec } from 'asn1-per-ts';

// Fixed-size BIT STRING (no length prefix)
const bitCodec = new BitStringCodec({ fixedSize: 16 });
const buf1 = BitBuffer.alloc();
bitCodec.encode(buf1, { bits: new Uint8Array([0xab, 0xcd]), length: 16 });

// Constrained OCTET STRING
const octetCodec = new OctetStringCodec({ minSize: 2, maxSize: 10 });
const buf2 = BitBuffer.alloc();
octetCodec.encode(buf2, new Uint8Array([0x01, 0x02, 0x03]));
```

### Encode strings

```typescript
import { BitBuffer, UTF8StringCodec } from 'asn1-per-ts';

const codec = new UTF8StringCodec({
  type: 'IA5String',
  minSize: 1,
  maxSize: 50,
});

const buffer = BitBuffer.alloc();
codec.encode(buffer, 'hello');
```

### Encode OBJECT IDENTIFIER

```typescript
import { BitBuffer, ObjectIdentifierCodec } from 'asn1-per-ts';

const codec = new ObjectIdentifierCodec();
const buffer = BitBuffer.alloc();
codec.encode(buffer, '1.2.840.113549.1.1');
```

OID values are encoded as dot-notation strings using BER contents octets (X.690 section 8.19) wrapped in a PER unconstrained length determinant. See `src/codecs/ObjectIdentifierCodec.ts`.

### Encode a SEQUENCE manually

```typescript
import { BitBuffer, SequenceCodec, IntegerCodec, BooleanCodec } from 'asn1-per-ts';

const codec = new SequenceCodec({
  fields: [
    { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
    { name: 'active', codec: new BooleanCodec() },
  ],
});

const buffer = BitBuffer.alloc();
codec.encode(buffer, { id: 42, active: true });
console.log(buffer.toHex()); // '2a80'
```

### Encode a CHOICE manually

```typescript
import { BitBuffer, ChoiceCodec, BooleanCodec, IntegerCodec } from 'asn1-per-ts';

const codec = new ChoiceCodec({
  alternatives: [
    { name: 'flag', codec: new BooleanCodec() },
    { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
  ],
});

const buffer = BitBuffer.alloc();
codec.encode(buffer, { count: 42 });
// Encodes CHOICE index 1 + value 42
```

### Encode SEQUENCE OF

```typescript
import { BitBuffer, SequenceOfCodec, IntegerCodec } from 'asn1-per-ts';

const codec = new SequenceOfCodec({
  itemCodec: new IntegerCodec({ min: 0, max: 255 }),
  minSize: 0,
  maxSize: 10,
});

const buffer = BitBuffer.alloc();
codec.encode(buffer, [10, 20, 30]);
```

## Multiple Encodings in One Buffer

You can encode multiple values sequentially into the same buffer:

```typescript
import { BitBuffer, IntegerCodec, BooleanCodec } from 'asn1-per-ts';

const intCodec = new IntegerCodec({ min: 0, max: 255 });
const boolCodec = new BooleanCodec();

const buffer = BitBuffer.alloc();
intCodec.encode(buffer, 42);     // 8 bits
boolCodec.encode(buffer, true);  // 1 bit
intCodec.encode(buffer, 100);    // 8 bits
// Total: 17 bits → 3 bytes with padding

const bytes = buffer.toUint8Array();
```

## Error Handling

Encoding throws errors when:
- A value is outside the constrained range (non-extensible INTEGER)
- An ENUMERATED value is not in the values list
- A CHOICE object has zero or multiple keys
- A required SEQUENCE field is missing
- A string exceeds the SIZE constraint

```typescript
const codec = new SchemaCodec({
  type: 'INTEGER',
  min: 0,
  max: 100,
});

try {
  codec.encodeToHex(200); // Throws: value outside range
} catch (err) {
  console.error(err.message);
}
```

## Related Files

| File | Description |
|---|---|
| `src/BitBuffer.ts` | `BitBuffer` - bit-level read/write buffer with auto-growth |
| `src/schema/SchemaCodec.ts` | `SchemaCodec` - high-level encode to hex/bytes |
| `src/schema/SchemaBuilder.ts` | `SchemaBuilder.build()` / `buildAll()` - builds codecs from SchemaNode |
| `src/codecs/Codec.ts` | `Codec<T>` interface with `encode(buffer, value)` method |
| `src/codecs/BooleanCodec.ts` | `BooleanCodec` |
| `src/codecs/IntegerCodec.ts` | `IntegerCodec` with constraint options |
| `src/codecs/EnumeratedCodec.ts` | `EnumeratedCodec` with extension support |
| `src/codecs/BitStringCodec.ts` | `BitStringCodec` with size constraints |
| `src/codecs/OctetStringCodec.ts` | `OctetStringCodec` with size constraints |
| `src/codecs/UTF8StringCodec.ts` | `UTF8StringCodec` for IA5String, VisibleString, UTF8String |
| `src/codecs/NullCodec.ts` | `NullCodec` |
| `src/codecs/ObjectIdentifierCodec.ts` | `ObjectIdentifierCodec` for OID dot-notation |
| `src/codecs/ChoiceCodec.ts` | `ChoiceCodec` with extension support |
| `src/codecs/SequenceCodec.ts` | `SequenceCodec` with OPTIONAL/DEFAULT fields |
| `src/codecs/SequenceOfCodec.ts` | `SequenceOfCodec` with size constraints |
| `cli/decode-uic-barcode.ts` | CLI tool showing real-world encoding/decoding |
