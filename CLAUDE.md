# CLAUDE.md

## Project overview

per-unaligned-ts is a TypeScript npm module for encoding and decoding ASN.1 PER (Packed Encoding Rules) unaligned data. It provides bit-level buffer management, constraint-based primitive codecs, and a schema-driven API for encoding/decoding JSON objects.

## Project structure

- `src/BitBuffer.ts` - Bit-level read/write buffer (MSB-first, auto-growing)
- `src/helpers.ts` - PER encoding primitives (constrained whole numbers, length determinants)
- `src/codecs/` - Individual type codecs (Boolean, Integer, Enumerated, BitString, OctetString, UTF8String, Null, Choice, Sequence, SequenceOf)
- `src/codecs/Codec.ts` - Base `Codec<T>` interface
- `src/schema/SchemaBuilder.ts` - Builds codec trees from JSON `SchemaNode` definitions
- `src/schema/SchemaCodec.ts` - High-level encode/decode with hex helpers
- `src/index.ts` - Public barrel exports
- `tests/` - Jest unit tests mirroring the src structure
- `website/` - React + TypeScript + TailwindCSS demo app (Vite, deployed to GitHub Pages)

## Commands

### Library (root directory)

- `npm test` - Run all unit tests with Jest
- `npm run build` - Build the library to `dist/` via TypeScript compiler
- `npx tsc --noEmit` - Type-check without emitting

### Website (`website/` directory)

- `npm run dev` - Start Vite dev server
- `npm run build` - Production build to `website/dist/` (uses `./` base path for GitHub Pages)
- `npx tsc --noEmit` - Type-check the website code

## Code conventions

- TypeScript strict mode enabled
- All type-only re-exports use `export type { ... }` (required by `isolatedModules` in website tsconfig)
- Codecs implement the `Codec<T>` interface with `encode(buffer, value)` and `decode(buffer)` methods
- Constraints are passed via constructor options objects
- Schema definitions use the `SchemaNode` discriminated union type
- Tests use Jest with `ts-jest` preset, test files live in `tests/` (not colocated)
- The website imports the library source directly via a Vite alias (`per-unaligned-ts` -> `../src`)

## CI/CD

- `.github/workflows/ci.yml` - Runs tests and build on every push/PR (Node 18, 20, 22)
- `.github/workflows/deploy.yml` - Deploys `website/dist/` to GitHub Pages on push to `main`
