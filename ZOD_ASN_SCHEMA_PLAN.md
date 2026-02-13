# Zod for ASN.1 Schema → Typed TypeScript Objects

## Problem Statement

Currently, all codecs operate on `unknown` types:
- `SchemaCodec.encode(value: unknown): Uint8Array`
- `SchemaCodec.decode(data: Uint8Array): unknown`
- `SequenceCodec` implements `Codec<Record<string, unknown>>`
- `ChoiceCodec` implements `Codec<ChoiceValue>` where `value: unknown`

Users must manually create TypeScript interfaces (as done in `intercode6-ts/src/types.ts`) and cast decoded values. There is no runtime validation of objects before encoding, and no typed output after decoding.

## Goal

Evaluate using [Zod](https://zod.dev) to:
1. **Generate Zod schemas from SchemaNode** — a function `schemaNodeToZod(node: SchemaNode)` that converts any ASN.1 JSON schema to a Zod schema
2. **Get TypeScript types automatically** — via `z.infer<typeof schema>` for compile-time types
3. **Validate before encoding** — parse input objects through the Zod schema before passing to the codec
4. **Type decoded output** — parse decoded `unknown` values through Zod to get typed results

## Approach: `schemaNodeToZod` Converter

Create a new module `src/schema/SchemaZod.ts` that converts `SchemaNode` → `z.ZodType`. This mirrors the structure of `SchemaBuilder.build()` but produces Zod schemas instead of codecs.

### Mapping: ASN.1 Types → Zod Schemas

| SchemaNode Type | Zod Schema | TypeScript Type | Notes |
|---|---|---|---|
| `BOOLEAN` | `z.boolean()` | `boolean` | Direct mapping |
| `NULL` | `z.null()` | `null` | Direct mapping |
| `INTEGER` | `z.number().int()` | `number` | Add `.min()/.max()` from constraints |
| `ENUMERATED` | `z.enum([...values])` | `"val1" \| "val2" \| ...` | Union of root + extension values |
| `BIT STRING` | `z.object({ data: z.instanceof(Uint8Array), bitLength: z.number() })` | `{ data: Uint8Array; bitLength: number }` | Matches `BitStringValue` |
| `OCTET STRING` | `z.instanceof(Uint8Array)` | `Uint8Array` | Direct mapping |
| `OBJECT IDENTIFIER` | `z.string()` | `string` | OID dot-notation |
| `IA5String` / `VisibleString` / `UTF8String` | `z.string()` | `string` | Add `.min()/.max()` from size constraints; add `.regex()` for alphabet constraint |
| `CHOICE` | `z.discriminatedUnion(...)` or `z.union(...)` | `{ key: "a"; value: X } \| { key: "b"; value: Y }` | See CHOICE section below |
| `SEQUENCE` | `z.object({...})` | `{ field1: T1; field2?: T2; ... }` | Optional fields use `.optional()` |
| `SEQUENCE OF` | `z.array(itemSchema)` | `T[]` | Add `.min()/.max()` from size constraints |
| `$ref` | Lazy resolution | (depends on target) | Use `z.lazy()` for recursion |

### CHOICE Representation — Two Options to Evaluate

The current `ChoiceCodec` uses `{ key: string; value: unknown }`. Zod offers two modeling strategies:

**Option A: Keep `{ key, value }` structure (compatible with current codecs)**
```typescript
// For CHOICE { count: INTEGER, flag: BOOLEAN }
z.union([
  z.object({ key: z.literal('count'), value: z.number().int() }),
  z.object({ key: z.literal('flag'), value: z.boolean() }),
])
```
- Pro: No codec changes needed
- Con: Verbose, not idiomatic TypeScript

**Option B: Discriminated single-key objects (more natural)**
```typescript
// { count: 42 } or { flag: true }
z.union([
  z.object({ count: z.number().int() }).strict(),
  z.object({ flag: z.boolean() }).strict(),
])
```
- Pro: More natural TypeScript objects
- Con: Requires a transform layer between Zod-validated input and codec `{ key, value }` format

**Recommendation**: Start with **Option A** to keep things simple and compatible. Option B can be added later as a transform layer.

### SEQUENCE with Optional/Default Fields

```typescript
// SEQUENCE { id: INTEGER, name: IA5String OPTIONAL, active: BOOLEAN DEFAULT TRUE }
z.object({
  id: z.number().int().min(0).max(255),
  name: z.string().optional(),          // optional → .optional()
  active: z.boolean().default(true),    // DEFAULT → .default(value)
})
```

This matches how the `SequenceCodec` already handles missing keys: optional fields can be omitted, and default fields use the default when absent.

### Handling `$ref` and Recursive Types

Use `z.lazy()` for `$ref` nodes, mirroring the `LazyCodec` pattern:

```typescript
function buildAllZod(schemas: Record<string, SchemaNode>): Record<string, z.ZodType> {
  const zodSchemas: Record<string, z.ZodType> = {};
  // First pass: create lazy references
  // Second pass: resolve
}
```

### Constraint Validation

Zod can enforce ASN.1 constraints at the schema level:

| Constraint | Zod Method |
|---|---|
| `INTEGER min/max` | `z.number().int().min(min).max(max)` |
| `String fixedSize` | `z.string().length(fixedSize)` |
| `String minSize/maxSize` | `z.string().min(minSize).max(maxSize)` |
| `SEQUENCE OF fixedSize` | `z.array(...).length(fixedSize)` |
| `SEQUENCE OF minSize/maxSize` | `z.array(...).min(minSize).max(maxSize)` |
| `ENUMERATED values` | `z.enum([...values])` (invalid values rejected) |
| `extensible` INTEGER/STRING | Relax constraints (don't add min/max) |

When `extensible` is true, constraints should be relaxed since values outside the root range are valid (they'll be encoded as extension values).

## Implementation Plan

### Step 1: Add Zod dependency

Add `zod` as a production dependency to `package.json`.

### Step 2: Create `src/schema/SchemaZod.ts`

Core converter function:

```typescript
import { z } from 'zod';
import type { SchemaNode } from './SchemaBuilder';

export function schemaNodeToZod(node: SchemaNode): z.ZodType {
  switch (node.type) {
    case 'BOOLEAN': return z.boolean();
    case 'NULL': return z.null();
    case 'INTEGER': ...
    case 'ENUMERATED': ...
    // ... all types
  }
}

export function schemaRegistryToZod(
  schemas: Record<string, SchemaNode>
): Record<string, z.ZodType> {
  // Handle $ref with z.lazy()
}
```

### Step 3: Create typed `SchemaCodec` wrapper

A `TypedSchemaCodec<T>` that wraps `SchemaCodec` with Zod validation:

```typescript
export class TypedSchemaCodec<T> {
  private codec: SchemaCodec;
  private zodSchema: z.ZodType<T>;

  constructor(schema: SchemaNode) {
    this.codec = new SchemaCodec(schema);
    this.zodSchema = schemaNodeToZod(schema) as z.ZodType<T>;
  }

  encode(value: T): Uint8Array {
    this.zodSchema.parse(value);  // Validate + type check
    return this.codec.encode(value);
  }

  decode(data: Uint8Array): T {
    const raw = this.codec.decode(data);
    return this.zodSchema.parse(raw);  // Validate + cast
  }
}
```

### Step 4: Tests for Basic Types

File: `tests/schema/SchemaZod.test.ts`

Test each basic type:
- **BOOLEAN**: `z.infer` produces `boolean`, validates `true`/`false`, rejects `"yes"`
- **NULL**: produces `null`, rejects `undefined`
- **INTEGER**: produces `number`, validates constraints (min/max), rejects floats/strings
- **INTEGER (extensible)**: accepts values outside root range
- **ENUMERATED**: produces union of literal strings, rejects unknown values
- **ENUMERATED with extensions**: includes extension values in the union
- **BIT STRING**: validates `{ data: Uint8Array, bitLength: number }` structure
- **OCTET STRING**: validates `Uint8Array` instances
- **String types** (IA5String, VisibleString, UTF8String): validates length constraints
- **OBJECT IDENTIFIER**: validates string type

### Step 5: Tests for SEQUENCE

File: same test file, SEQUENCE section

- **All required fields**: validates complete objects, rejects missing fields
- **Optional fields**: accepts objects with and without optional fields
- **Default values**: fills in defaults for missing fields via `.default()`
- **Nested SEQUENCE**: recursive type inference works
- **Extension fields**: extension fields are optional in the Zod schema
- **Round-trip with codec**: encode with `TypedSchemaCodec`, decode, verify types match

### Step 6: Tests for CHOICE and SEQUENCE OF

- **CHOICE**: validates discriminated union structure
- **SEQUENCE OF**: validates array with item type checking
- **Complex nesting**: SEQUENCE containing CHOICE and SEQUENCE OF fields

### Step 7: Test with Real Schema

Load `schemas/uic-barcode/intercode6.schema.json`, convert to Zod, and:
- Validate that a known good Intercode object passes validation
- Verify that a malformed object is rejected with meaningful errors
- Round-trip encode/decode with typed codec

## Key Design Decisions

1. **Zod as production dependency** — It's needed at runtime for validation, not just types. Zod is ~13KB minified+gzipped, acceptable for a codec library.

2. **Separate from existing codecs** — `SchemaZod.ts` is a parallel module, not a modification of `SchemaBuilder`. Existing untyped API remains unchanged.

3. **`z.infer` for type extraction** — Users can derive TypeScript types without manually writing interfaces:
   ```typescript
   const zodSchema = schemaNodeToZod(mySchemaNode);
   type MyType = z.infer<typeof zodSchema>;
   ```

4. **Extensible types relax constraints** — When `extensible: true`, min/max constraints are not applied in Zod since extension values legitimately exceed root constraints.

5. **`$ref` uses `z.lazy()`** — Matches the `LazyCodec` pattern for recursive types.

## File Changes Summary

| File | Action |
|---|---|
| `package.json` | Add `zod` dependency |
| `src/schema/SchemaZod.ts` | **New** — `schemaNodeToZod()`, `schemaRegistryToZod()` |
| `src/schema/TypedSchemaCodec.ts` | **New** — Typed encode/decode wrapper |
| `src/index.ts` | Export new modules |
| `tests/schema/SchemaZod.test.ts` | **New** — Tests for all type mappings |
| `tests/schema/TypedSchemaCodec.test.ts` | **New** — Integration tests with real encode/decode |

## Risks and Considerations

- **Bundle size**: Zod adds ~13KB gzipped. For a codec library this may be significant. Could make it an optional peer dependency instead.
- **Uint8Array validation**: `z.instanceof(Uint8Array)` works at runtime but doesn't serialize to JSON schema if that's ever needed.
- **CHOICE structure**: The `{ key, value }` format is codec-internal. A future improvement could offer a more natural API with automatic transformation.
- **Default values in Zod vs codec**: Both Zod `.default()` and `SequenceCodec` `defaultValue` handle defaults. Need to ensure they agree and don't double-apply.
- **Extension fields**: Treating them as optional in Zod is correct for encoding but decoded output will always have them present or absent based on wire data. Zod `.optional()` handles both cases.
