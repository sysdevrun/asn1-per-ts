# Decoding Binary Data

Decode PER unaligned binary data back into JavaScript/TypeScript objects.

## Overview

There are two levels of decoding API:

1. **High-level**: `SchemaCodec` (`src/schema/SchemaCodec.ts`) - decode a `Uint8Array` or hex string into a plain object using a `SchemaNode` definition.
2. **Metadata decoding**: `decodeWithMetadata` returns a `DecodedNode` tree with bit positions, raw bytes, and codec references for every field. Use `stripMetadata` to convert back to a plain object.
3. **Low-level**: Individual codec classes (`src/codecs/`) + `BitBuffer` (`src/BitBuffer.ts`) - decode directly from a bit-level buffer.

## High-Level Decoding with SchemaCodec

### Decode from hex string

```typescript
import { SchemaCodec } from 'per-unaligned-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
  ],
});

const decoded = codec.decodeFromHex('2a80');
// decoded === { id: 42, active: true }
```

`SchemaCodec.decodeFromHex()` converts the hex string to bytes internally and runs the decoder. See `src/schema/SchemaCodec.ts:37`.

### Decode from Uint8Array

```typescript
const bytes = new Uint8Array([0x2a, 0x80]);
const decoded = codec.decode(bytes);
// decoded === { id: 42, active: true }
```

`SchemaCodec.decode()` wraps the `Uint8Array` in a `BitBuffer` and calls the underlying codec's `decode()` method. See `src/schema/SchemaCodec.ts:31`.

### Decode with OPTIONAL / DEFAULT fields

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'nickname', schema: { type: 'IA5String' }, optional: true },
    { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
  ],
});

// Encode with all fields present
const hex1 = codec.encodeToHex({ id: 5, nickname: 'hello', version: 3 });
const result1 = codec.decodeFromHex(hex1);
// result1 === { id: 5, nickname: 'hello', version: 3 }

// Encode with optional/default fields absent
const hex2 = codec.encodeToHex({ id: 5 });
const result2 = codec.decodeFromHex(hex2);
// result2 === { id: 5, version: 1 }
// nickname is absent (undefined), version falls back to defaultValue
```

### Decode ENUMERATED values

```typescript
const codec = new SchemaCodec({
  type: 'ENUMERATED',
  values: ['pending', 'approved', 'rejected'],
});

const decoded = codec.decodeFromHex('40');
// decoded === 'approved' (index 1 in the enumeration)
```

### Decode CHOICE values

```typescript
const codec = new SchemaCodec({
  type: 'CHOICE',
  alternatives: [
    { name: 'flag', schema: { type: 'BOOLEAN' } },
    { name: 'count', schema: { type: 'INTEGER', min: 0, max: 255 } },
  ],
});

const decoded = codec.decodeFromHex('95');
// decoded === { count: 42 } — the CHOICE index selects 'count'
```

CHOICE values decode as an object with a single key matching the chosen alternative name.

## Decoding with Metadata

Every codec has a `decodeWithMetadata` method that returns a `DecodedNode` tree. Each node wraps the decoded value with metadata about its encoding: bit offset, bit length, raw bytes, the codec that decoded it, and schema flags (optional, present, default, extension).

### High-level metadata decoding

```typescript
import { SchemaCodec, stripMetadata } from 'per-unaligned-ts';
import type { DecodedNode } from 'per-unaligned-ts';

const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
    { name: 'name', schema: { type: 'IA5String', minSize: 1, maxSize: 50 }, optional: true },
  ],
});

const hex = codec.encodeToHex({ id: 42, active: true, name: 'hello' });
const node = codec.decodeFromHexWithMetadata(hex);
```

`SchemaCodec.decodeFromHexWithMetadata()` and `SchemaCodec.decodeWithMetadata()` return a `DecodedNode` instead of a plain object.

### Inspecting the DecodedNode tree

```typescript
// The root node wraps a SEQUENCE — value is Record<string, DecodedNode>
const fields = node.value as Record<string, DecodedNode>;

// Each field has a value and metadata
console.log(fields.id.value);           // 42
console.log(fields.id.meta.bitOffset);  // 0
console.log(fields.id.meta.bitLength);  // 8
console.log(fields.id.meta.rawBytes);   // Uint8Array — the raw PER encoding of this field

console.log(fields.active.value);           // true
console.log(fields.active.meta.bitOffset);  // 8 (starts right after id)
console.log(fields.active.meta.bitLength);  // 1

// Optional field metadata
console.log(fields.name.meta.optional);  // true
console.log(fields.name.meta.present);   // true (was encoded)
```

### FieldMeta properties

| Property | Type | Description |
|----------|------|-------------|
| `bitOffset` | `number` | Start bit position in the source buffer |
| `bitLength` | `number` | Number of bits consumed |
| `rawBytes` | `Uint8Array` | Raw PER encoding of this value, left-aligned |
| `codec` | `Codec<unknown>` | The codec instance that decoded this node |
| `optional` | `boolean?` | Whether the schema declared this field OPTIONAL |
| `present` | `boolean?` | Whether this field was actually present in encoding |
| `isDefault` | `boolean?` | Whether the DEFAULT value was used |
| `isExtension` | `boolean?` | Whether this field is an extension addition |

### Value shapes by codec type

- **Primitive codecs** (Boolean, Integer, Enumerated, etc.): `value` is the raw JS value (`boolean`, `number`, `string`, etc.)
- **SequenceCodec**: `value` is `Record<string, DecodedNode>` — each field is a wrapped node
- **SequenceOfCodec**: `value` is `DecodedNode[]` — each array item is a wrapped node
- **ChoiceCodec**: `value` is `{ key: string; value: DecodedNode }` — the selected alternative is a wrapped node

### OPTIONAL / DEFAULT field handling

For absent OPTIONAL fields (not present, no default), the tree includes a node with `value: undefined`, `present: false`, `bitLength: 0`. For DEFAULT fields using the default value, the node has `value: <defaultValue>`, `isDefault: true`, `present: false`.

```typescript
const codec = new SchemaCodec({
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'name', schema: { type: 'IA5String', minSize: 1, maxSize: 50 }, optional: true },
    { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
  ],
});

const hex = codec.encodeToHex({ id: 5 });
const node = codec.decodeFromHexWithMetadata(hex);
const fields = node.value as Record<string, DecodedNode>;

// Absent optional field
console.log(fields.name.meta.present);   // false
console.log(fields.name.meta.optional);  // true
console.log(fields.name.value);          // undefined

// Default field (not explicitly encoded)
console.log(fields.version.meta.present);   // false
console.log(fields.version.meta.isDefault); // true
console.log(fields.version.value);          // 1
```

### Converting back to a plain object with stripMetadata

`stripMetadata` walks the `DecodedNode` tree and reconstructs a plain object identical to `decode()`:

```typescript
import { stripMetadata } from 'per-unaligned-ts';

const node = codec.decodeFromHexWithMetadata(hex);
const plain = stripMetadata(node);
// plain is identical to codec.decodeFromHex(hex)
```

`stripMetadata` dispatches on the codec stored in each node's metadata using `instanceof` checks. It throws if it encounters an unhandled codec type.

### Low-level metadata decoding

Every codec class also supports `decodeWithMetadata`:

```typescript
import { BitBuffer, IntegerCodec } from 'per-unaligned-ts';

const codec = new IntegerCodec({ min: 0, max: 255 });
const buffer = BitBuffer.from(new Uint8Array([0x2a]));
const node = codec.decodeWithMetadata(buffer);

console.log(node.value);           // 42
console.log(node.meta.bitOffset);  // 0
console.log(node.meta.bitLength);  // 8
console.log(node.meta.rawBytes);   // Uint8Array([0x2a])
console.log(node.meta.codec);      // the IntegerCodec instance
```

### BitBuffer.extractBits

The `extractBits` method extracts a range of bits into a new byte-aligned `Uint8Array`. This is used internally by `decodeWithMetadata` to populate `rawBytes`.

```typescript
const buffer = BitBuffer.from(new Uint8Array([0xab, 0xcd]));
const raw = buffer.extractBits(4, 8);
// raw === Uint8Array([0xbc]) — bits 4..11 extracted and left-aligned
```

## Decoding with Pre-generated Schemas

For complex real-world protocols, load pre-generated schema JSON files from the `schemas/` directory:

```typescript
import { SchemaCodec, SchemaBuilder, type SchemaNode } from 'per-unaligned-ts';
import headerSchemas from './schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';

// Simple schema (no $ref nodes) — use SchemaCodec directly
const codec = new SchemaCodec(
  headerSchemas.UicBarcodeHeader as unknown as SchemaNode,
);

const decoded = codec.decodeFromHex('...');
```

For schemas with recursive types (`$ref` nodes), use `SchemaBuilder.buildAll()`:

```typescript
import { SchemaBuilder, BitBuffer, type SchemaNode } from 'per-unaligned-ts';
import railTicketSchemas from './schemas/uic-barcode/uicRailTicketData_v2.schema.json';

const codecs = SchemaBuilder.buildAll(
  railTicketSchemas as unknown as Record<string, SchemaNode>,
);

const buffer = BitBuffer.from(someBytes);
const ticket = codecs.UicRailTicketData.decode(buffer);
```

See `cli/decode-uic-barcode.ts` for a complete example of decoding nested UIC barcode data with multiple schema files and dispatch logic.

## Decoding from ASN.1 Text (Parse + Decode)

Combine the parser with decoding in one pipeline:

```typescript
import {
  parseAsn1Module,
  convertModuleToSchemaNodes,
  SchemaCodec,
} from 'per-unaligned-ts';

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

const decoded = codec.decodeFromHex('002a05776f726c64');
// decoded === { id: 42, text: 'world' }
```

## Low-Level Decoding with BitBuffer and Codecs

For fine-grained control, use `BitBuffer` (`src/BitBuffer.ts`) with individual codec classes from `src/codecs/`.

### BitBuffer basics

```typescript
import { BitBuffer } from 'per-unaligned-ts';

// Create a read buffer from bytes
const buffer = BitBuffer.from(new Uint8Array([0x2a, 0x80]));

console.log(buffer.bitLength);  // 16
console.log(buffer.remaining);  // 16

// Read individual bits
const bit = buffer.readBit();   // 0 or 1
buffer.reset();                  // seek back to start

// Read multiple bits as unsigned integer
const value = buffer.readBits(8); // reads 8 bits → 0x2a = 42
```

### Create buffer from hex

```typescript
const hex = '2a80';
const bytes = new Uint8Array(
  hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)),
);
const buffer = BitBuffer.from(bytes);
```

### Create buffer from binary string

```typescript
const buffer = BitBuffer.fromBinaryString('00101010');
// buffer contains byte 0x2a
```

### Decode a constrained INTEGER

```typescript
import { BitBuffer, IntegerCodec } from 'per-unaligned-ts';

const codec = new IntegerCodec({ min: 0, max: 255 });
const buffer = BitBuffer.from(new Uint8Array([0x2a]));
const value = codec.decode(buffer);
// value === 42
```

Options for `IntegerCodec` (see `src/codecs/IntegerCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `min` | `number` | Lower bound of the value range |
| `max` | `number` | Upper bound of the value range |
| `extensible` | `boolean` | If true, a 1-bit extension marker prefixes the encoding |

### Decode a BOOLEAN

```typescript
import { BitBuffer, BooleanCodec } from 'per-unaligned-ts';

const codec = new BooleanCodec();
const buffer = BitBuffer.from(new Uint8Array([0x80])); // MSB = 1
const value = codec.decode(buffer);
// value === true
```

### Decode an ENUMERATED

```typescript
import { BitBuffer, EnumeratedCodec } from 'per-unaligned-ts';

const codec = new EnumeratedCodec({
  values: ['red', 'green', 'blue'],
});

const buffer = BitBuffer.from(new Uint8Array([0x80])); // index 1 → 'green'
const value = codec.decode(buffer);
// value === 'green'
```

Options for `EnumeratedCodec` (see `src/codecs/EnumeratedCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `values` | `string[]` | Root enumeration values |
| `extensionValues` | `string[]` | Extension enumeration values (makes type extensible) |

### Decode BIT STRING and OCTET STRING

```typescript
import { BitBuffer, BitStringCodec, OctetStringCodec } from 'per-unaligned-ts';

// Fixed-size BIT STRING (no length prefix in encoding)
const bitCodec = new BitStringCodec({ fixedSize: 8 });
const buf1 = BitBuffer.from(new Uint8Array([0xff]));
const bits = bitCodec.decode(buf1);
// bits === { bits: Uint8Array([0xff]), length: 8 }

// Constrained OCTET STRING
const octetCodec = new OctetStringCodec({ minSize: 2, maxSize: 10 });
const buf2 = BitBuffer.from(new Uint8Array([/* encoded data */]));
const octets = octetCodec.decode(buf2);
// octets is a Uint8Array
```

Options for `BitStringCodec` (see `src/codecs/BitStringCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `fixedSize` | `number` | Exact bit length (no length determinant) |
| `minSize` | `number` | Minimum bit length |
| `maxSize` | `number` | Maximum bit length |
| `extensible` | `boolean` | 1-bit extension marker prefix |

Options for `OctetStringCodec` (see `src/codecs/OctetStringCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `fixedSize` | `number` | Exact byte length (no length determinant) |
| `minSize` | `number` | Minimum byte length |
| `maxSize` | `number` | Maximum byte length |
| `extensible` | `boolean` | 1-bit extension marker prefix |

### Decode strings

```typescript
import { BitBuffer, UTF8StringCodec } from 'per-unaligned-ts';

const codec = new UTF8StringCodec({
  type: 'IA5String',
  minSize: 1,
  maxSize: 50,
});

const buffer = BitBuffer.from(someBytes);
const text = codec.decode(buffer);
// text is a string
```

Options for `UTF8StringCodec` (see `src/codecs/UTF8StringCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `type` | `'IA5String' \| 'VisibleString' \| 'UTF8String'` | String type (determines character set) |
| `alphabet` | `string` | Custom alphabet constraint (reduces bits per character) |
| `fixedSize` | `number` | Exact character length |
| `minSize` | `number` | Minimum character length |
| `maxSize` | `number` | Maximum character length |
| `extensible` | `boolean` | 1-bit extension marker prefix |

### Decode SEQUENCE manually

```typescript
import { BitBuffer, SequenceCodec, IntegerCodec, BooleanCodec } from 'per-unaligned-ts';

const codec = new SequenceCodec({
  fields: [
    { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
    { name: 'active', codec: new BooleanCodec() },
  ],
});

const buffer = BitBuffer.from(new Uint8Array([0x2a, 0x80]));
const value = codec.decode(buffer);
// value === { id: 42, active: true }
```

Options for `SequenceCodec` (see `src/codecs/SequenceCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `fields` | `SequenceField[]` | Array of `{ name, codec, optional?, defaultValue? }` |
| `extensionFields` | `SequenceField[]` | Extension fields (makes type extensible) |

### Decode CHOICE manually

```typescript
import { BitBuffer, ChoiceCodec, BooleanCodec, IntegerCodec } from 'per-unaligned-ts';

const codec = new ChoiceCodec({
  alternatives: [
    { name: 'flag', codec: new BooleanCodec() },
    { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
  ],
});

const buffer = BitBuffer.from(new Uint8Array([0x95]));
const value = codec.decode(buffer);
// value === { count: 42 }
```

Options for `ChoiceCodec` (see `src/codecs/ChoiceCodec.ts`):

| Option | Type | Description |
|---|---|---|
| `alternatives` | `ChoiceAlternative[]` | Array of `{ name, codec }` |
| `extensionAlternatives` | `ChoiceAlternative[]` | Extension alternatives (makes type extensible) |

### Decode SEQUENCE OF

```typescript
import { BitBuffer, SequenceOfCodec, IntegerCodec } from 'per-unaligned-ts';

const codec = new SequenceOfCodec({
  itemCodec: new IntegerCodec({ min: 0, max: 255 }),
  minSize: 0,
  maxSize: 10,
});

const buffer = BitBuffer.from(someBytes);
const items = codec.decode(buffer);
// items is an array of numbers
```

### Decode OBJECT IDENTIFIER

```typescript
import { BitBuffer, ObjectIdentifierCodec } from 'per-unaligned-ts';

const codec = new ObjectIdentifierCodec();
const buffer = BitBuffer.from(someBytes);
const oid = codec.decode(buffer);
// oid is a string like '1.2.840.113549.1.1'
```

## Real-World Example: Decoding UIC Barcode

The `cli/decode-uic-barcode.ts` tool demonstrates a complete decoding pipeline:

1. Load pre-generated schemas from `schemas/uic-barcode/`
2. Build codecs with `SchemaBuilder.buildAll()` for schemas containing `$ref` nodes
3. Decode the outer `UicBarcodeHeader` structure
4. Dispatch on `dataFormat` to decode nested data blocks (FCB2 rail ticket data)
5. Dispatch on `extensionId` patterns to decode Intercode 6 extensions

```typescript
import { SchemaCodec, SchemaBuilder, BitBuffer, type SchemaNode } from 'per-unaligned-ts';
import headerSchemas from './schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';
import railTicketSchemas from './schemas/uic-barcode/uicRailTicketData_v2.schema.json';

// Header uses no $ref → SchemaCodec
const headerCodec = new SchemaCodec(
  headerSchemas.UicBarcodeHeader as unknown as SchemaNode,
);

// Rail ticket data uses $ref → SchemaBuilder.buildAll()
const railCodecs = SchemaBuilder.buildAll(
  railTicketSchemas as unknown as Record<string, SchemaNode>,
);

// Decode header from hex
const header = headerCodec.decodeFromHex(hexData) as any;

// Decode nested FCB data block
const dataBlock = header.level2SignedData.level1Data.dataSequence[0];
const ticketBuffer = BitBuffer.from(dataBlock.data);
const ticket = railCodecs.UicRailTicketData.decode(ticketBuffer);
```

See `cli/decode-uic-barcode.ts` for the full implementation.

## Related Files

| File | Description |
|---|---|
| `src/BitBuffer.ts` | `BitBuffer` - bit-level read/write buffer |
| `src/schema/SchemaCodec.ts` | `SchemaCodec` - high-level decode from hex/bytes |
| `src/schema/SchemaBuilder.ts` | `SchemaBuilder.build()` / `buildAll()` - builds codecs from SchemaNode |
| `src/codecs/Codec.ts` | `Codec<T>` interface with `decode(buffer)` and `decodeWithMetadata(buffer)` methods |
| `src/codecs/DecodedNode.ts` | `DecodedNode`, `FieldMeta` interfaces and `primitiveDecodeWithMetadata` helper |
| `src/codecs/stripMetadata.ts` | `stripMetadata` function — converts `DecodedNode` tree back to plain object |
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
| `cli/decode-uic-barcode.ts` | CLI tool for decoding UIC barcode headers |
