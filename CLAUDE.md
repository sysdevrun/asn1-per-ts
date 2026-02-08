# CLAUDE.md

## Project overview

per-unaligned-ts is a TypeScript npm module for encoding and decoding ASN.1 PER (Packed Encoding Rules) unaligned data. It provides bit-level buffer management, constraint-based primitive codecs, and a schema-driven API for encoding/decoding JSON objects.

**The `intercode6-ts/` module is the main encoding/decoding library built on top of per-unaligned-ts.** Most encoding and decoding work should use intercode6-ts — understanding the low-level primitives in `src/` is usually not required.

The `examples/` directory contains guides that should be sufficient for most usage.

## Project structure

- `intercode6-ts/` - **Intercode Part 6 encoding/decoding npm module** (high-level API for real-world use)
- `src/` - Low-level PER primitives (bit buffers, codecs, schema builder, ASN.1 parser)
- `tests/` - Jest unit tests mirroring the src structure
- `schemas/` - Pre-generated SchemaNode JSON files from real-world ASN.1 specifications
- `examples/` - Usage guides (encoding, decoding, schema parsing)
  - `examples/schema-parser.md` - Parsing ASN.1 text to SchemaNode, constraint options, CLI usage
  - `examples/encoding.md` - Encoding objects to PER unaligned binary (high-level and low-level APIs)
  - `examples/decoding.md` - Decoding PER unaligned binary back to objects (high-level and low-level APIs)
- `cli/` - CLI scripts (schema generation, UIC barcode decoding)
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

## Prompt history

Every prompt given to edit this project must be appended to `PROMPT.md` as a new section, so the file contains a complete history of all prompts used to generate and evolve the project.
