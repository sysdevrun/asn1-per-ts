# Parser & PER Codec Fuzzing

Fuzzing infrastructure for the ASN.1 PER unaligned encoder/decoder, the ASN.1 schema text parser (`parseAsn1Module`), and the AST-to-SchemaNode converter (`convertModuleToSchemaNodes`).

## Evaluation: Why Fuzz?

### PER Unaligned Codec

The PER codec operates at the bit level, encoding/decoding values according to constraint-driven rules. Edge cases include:

| Risk | Description | Fuzzing approach |
|------|-------------|------------------|
| **Decode crash on malformed bytes** | Arbitrary byte sequences fed to decoders | Random bytes decode fuzzing |
| **Round-trip mismatch** | encode(x) decoded back produces different value | Round-trip with random valid values |
| **Off-by-one bit errors** | Misaligned reads across byte boundaries, especially for non-byte-aligned types | Random constraint ranges + values |
| **Constraint edge cases** | Single-value ranges (0 bits), extensible out-of-range values, zero-size collections | Boundary value generation |
| **Composite codec interaction** | SEQUENCE preamble bits, CHOICE index encoding, extension open-type framing | Random optional/default field presence |
| **Buffer underrun** | Truncated data, partial fields, missing length determinants | Short random byte arrays |
| **Length determinant bugs** | Unconstrained/semi-constrained lengths with unusual byte counts | Random bytes through length-encoded types |

### ASN.1 Text Parser

The parser accepts arbitrary string input through PEG grammar parsing and AST-to-SchemaNode conversion. See below for parser-specific risks.

## Test Files

### PER Codec Tests

- **`fuzz-per-codec.test.ts`** — Round-trip fuzzing (65 tests, 200+ iterations each)
  - Every codec type: Boolean, Integer, Enumerated, BitString, OctetString, UTF8String/IA5String/VisibleString, OID, Null
  - Composite codecs: Sequence (optional/default fields), Choice, SequenceOf
  - SchemaCodec high-level API
  - Random constraint ranges, boundary values, extensible in/out of range
  - Sequential multi-codec encoding in shared buffer

- **`fuzz-per-decode.test.ts`** — Arbitrary bytes decode fuzzing (39 tests, 300 iterations each)
  - Every codec type with random bytes: must decode or throw clean Error
  - Multiple constraint configurations per codec type
  - `decodeWithMetadata()` validation
  - BitBuffer edge cases (empty buffer, exact-size reads, random readBits/readOctets)
  - Encoder constraint violation verification

### Parser Tests

- **`fuzz-parser.test.ts`** — Grammar-aware generation and mutation of ASN.1 text
- **`fuzz-converter.test.ts`** — Full pipeline (parse + convert) with SchemaNode validation

## Directory Structure

```
fuzzing/
  README.md                        # This file
  jest.config.cjs                  # Jest config for running fuzz tests
  seeds.ts                         # Seed corpus of valid ASN.1 inputs
  generators/
    asn1-generator.ts              # Grammar-aware random ASN.1 generator
    mutator.ts                     # Mutation strategies for strings
  fuzz-per-codec.test.ts           # PER encode/decode round-trip fuzzing
  fuzz-per-decode.test.ts          # PER decoding of arbitrary/malformed bytes
  fuzz-parser.test.ts              # Fuzz tests for parseAsn1Module
  fuzz-converter.test.ts           # Fuzz tests for full pipeline
  run.ts                           # Standalone continuous parser fuzzer script
```

## Running

```bash
# Run all fuzz tests
npx jest --config fuzzing/jest.config.cjs

# Run only PER codec fuzz tests
npx jest --config fuzzing/jest.config.cjs fuzz-per

# Run only parser fuzz tests
npx jest --config fuzzing/jest.config.cjs fuzz-parser

# Control iteration count via environment variable
FUZZ_ITERATIONS=1000 npx jest --config fuzzing/jest.config.cjs

# Standalone continuous parser fuzzer (runs until stopped or crash found)
npx ts-node fuzzing/run.ts

# With iteration limit
npx ts-node fuzzing/run.ts --iterations 10000
```

## Known Findings

- **PEG parser backtracking**: Pathological input strings (e.g., long ambiguous token sequences) can cause the Peggy PEG parser to hang due to exponential backtracking. The fuzz harness caps input length at 2KB to mitigate this. This is a real denial-of-service risk if the parser accepts untrusted input.

## Extending

To add new seed inputs, add entries to `seeds.ts`. Good seeds are valid ASN.1 modules that exercise specific grammar features.

To add new mutation strategies, add functions to `generators/mutator.ts` and register them in the `MUTATORS` array.

To add new PER codec fuzz scenarios, add test cases to `fuzz-per-codec.test.ts` (round-trip) or `fuzz-per-decode.test.ts` (random bytes).
