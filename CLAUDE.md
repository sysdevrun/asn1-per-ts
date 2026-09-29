# CLAUDE.md

## Project overview

asn1-per-ts is a TypeScript npm module for encoding and decoding ASN.1 PER (Packed Encoding Rules) unaligned data. It provides bit-level buffer management, constraint-based primitive codecs, and a schema-driven API for encoding/decoding JSON objects.

The `examples/` directory contains guides that should be sufficient for most usage.

## Project structure

- `src/` - PER primitives (bit buffers, codecs, schema builder, ASN.1 parser)
  - `src/schema/` - `SchemaNode` interchange format, `SchemaBuilder`, `SchemaCodec`, `Infer` types, `TypedCodec`
  - `src/dsl/` - The `asn` builder DSL, compiling down to `SchemaNode`
  - `src/codegen/` - `SchemaNode` registry to TypeScript source
  - `src/cli/` - The `asn1-per-ts` binary (`cli.ts` is the testable router, `main.ts` the Node entry point)
- `tests/` - Jest unit tests mirroring the src structure
- `examples/` - Usage guides (encoding, decoding, schema parsing)
  - `examples/schema-parser.md` - Parsing ASN.1 text to SchemaNode, constraint options, CLI usage
  - `examples/typed-api.md` - Type inference from a schema: `Infer`/`InferInput`/`InferMetadata`, typed `SchemaCodec`, `$ref` registries
  - `examples/dsl.md` - The `asn` builder DSL: types carried in the value rather than inferred from literals
  - `examples/codegen.md` - Generating TypeScript types and codecs from an ASN.1 file
  - `examples/encoding.md` - Encoding objects to PER unaligned binary (high-level and low-level APIs)
  - `examples/decoding.md` - Decoding PER unaligned binary back to objects (high-level and low-level APIs)
- `website/` - React + TypeScript + TailwindCSS demo app (Vite, deployed to GitHub Pages)
- `CHANGELOG.md` - Notable changes, newest first. Add to `## [Unreleased]` when changing public API or behaviour; `PUBLISH.md` folds it into a release

## Commands

### Library (root directory)

- `npm test` - Run all unit tests with Jest
- `npm run build` - Build the library to `dist/` via TypeScript compiler
- `npx tsc --noEmit` - Type-check without emitting
- `npx tsx src/cli/main.ts types <in.asn> [out.ts]` - Run the CLI from source
- Regenerate the codegen fixture after changing the generator:
  `npx tsx src/cli/main.ts types tests/fixtures/sample-module.asn tests/fixtures/generated/sampleModule.ts --import-from ../../../src/index.js`

### Website (`website/` directory)

- `npm run dev` - Start Vite dev server
- `npm run build` - Production build to `website/dist/` (uses `./` base path for GitHub Pages)
- `npx tsc --noEmit` - Type-check the website code

## Code conventions

- TypeScript strict mode enabled
- All type-only re-exports use `export type { ... }` (required by `isolatedModules` in website tsconfig)
- Codecs implement the `Codec<T>` interface with `encode(buffer, value)` and `decode(buffer)` methods
- Constraints are passed via constructor options objects
- Schema definitions use the `SchemaNode` discriminated union type (`src/schema/SchemaNode.ts`), whose collections are `readonly` so inline schemas keep their literal types
- `SchemaCodec`, `SchemaBuilder.build` and `createCodec(s)` take the schema as a `const` type parameter; the encoded/decoded/metadata types are computed from it by `src/schema/Infer.ts`. Anything typed as the wide `SchemaNode` union degrades to `unknown`
- Every front-end (inline `SchemaNode`, `asn` DSL, codegen) compiles to a `SchemaNode` and returns the same `TypedCodec<TOut, TIn, TNode>` interface. Keep that true when adding features
- `RawBytes` passthrough is reached via `codec.raw`, never the default encode signatures — it used to widen every node and doubled the length of every encode error
- `tests/fixtures/generated/sampleModule.ts` is checked-in codegen output; `tests/codegen/generatedModule.test.ts` asserts the generator still reproduces it, and ts-jest compiles it
- The CLI lives in `src/` so the build ships it as the `asn1-per-ts` bin. Keep the argument handling in `src/cli/cli.ts` behind the `CliIo` interface — `src/cli/main.ts` is the only part that touches `fs` or `process`, and the tests drive `runCli` with an in-memory IO
- Tests use Jest with `ts-jest` preset, test files live in `tests/` (not colocated)
- The website imports the library source directly via a Vite alias (`asn1-per-ts` -> `../src`)

## CI/CD

- `.github/workflows/ci.yml` - Runs tests and build on every push/PR (Node 18, 20, 22)
- `.github/workflows/deploy.yml` - Deploys `website/dist/` to GitHub Pages on push to `main`

## Prompt history

Every prompt given to edit this project must be appended to `PROMPT.md` as a new section, so the file contains a complete history of all prompts used to generate and evolve the project.
