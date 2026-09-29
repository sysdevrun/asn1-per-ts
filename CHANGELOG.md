# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
For a TypeScript library, a change that makes previously-compiling code fail to
compile counts as a breaking change even when the runtime behaviour is untouched.

Releases before this file was added are documented in the
[GitHub releases](https://github.com/sysdevrun/asn1-per-ts/releases)
(`v1.0.2` through `v1.4.0`).

## [Unreleased]

Typed encoding and decoding. `decode()` used to return `unknown` and `encode()`
used to accept `unknown`, so callers wrote their own interfaces and cast. The
types are now derived from the schema, three ways: from an inline `SchemaNode`
literal, from the `asn` builder DSL, or from TypeScript generated out of a `.asn`
file. All three compile to a `SchemaNode` — the interchange format — and return
the same `TypedCodec<TOut, TIn, TNode>`.

None of this runs at runtime: no validation was added, no dependency was added,
and the emitted JavaScript is unchanged.

### Added

- `Infer<S>`, `InferInput<S>`, `InferInputRaw<S>` and `InferMetadata<S>`: the
  decoded type, the accepted encode type, the same allowing pre-encoded
  `RawBytes`, and the `decodeWithMetadata` tree, computed from a schema's literal
  type. ENUMERATED narrows to a literal union, CHOICE becomes a discriminated
  union on `key`, OPTIONAL fields become optional properties, and DEFAULT fields
  are required after decoding but omittable when encoding.
- `defineSchema`, `defineSchemas`, `createCodec` and `createCodecs` for declaring
  schemas without `as const`. `createCodecs` resolves `$ref` between the schemas
  of a registry, in the types as well as at runtime.
- `TypedCodec<TOut, TIn, TNode>`, the interface every front-end returns, plus
  `RawInput<T>` and `RawEncoder<TIn>`.
- `codec.raw`, an encoding view accepting pre-encoded `RawBytes` at any node.
- `asn` builder DSL (`src/dsl/`): `asn.sequence`, `asn.choice`, `asn.sequenceOf`,
  the primitive builders, `.optional()`, `.default(value)`, `asn.ref<T>(name)`,
  `asn.codec`, `asn.compile`, `asn.toSchemaNode` and `asn.toSchemaRegistry`.
  Types travel in the value's type parameters rather than being recomputed from
  literals, so a schema keeps its type through a plain `const` and type errors
  name the offending field. `SchemaFor<T>`, `TypeOf`, `InputOf` and `NodeOf`
  read the types back out.
- Code generation (`src/codegen/`): `generateTypeScript(schemas, options)` turns
  a `SchemaNode` registry into a module of named interfaces and typed codecs.
  Structures the ASN.1 parser inlined are matched back to the types they came
  from, so the output references `IssuingDetail` instead of repeating its shape.
  ASN.1 hyphens are handled both ways — type names become PascalCase, field
  names stay verbatim and quoted.
- An `asn1-per-ts` executable, installed by the package:
  `asn1-per-ts types <in.asn|in.json> [out.ts]` generates TypeScript and
  `asn1-per-ts schema <in.asn> [out.json]` generates a `SchemaNode` registry.
  Data goes to stdout and progress to stderr, so redirecting produces a clean
  file; failures print a message and exit `1`.
- `Stripped<N>` and `Simplify<T>` type helpers; `SchemaRegistry`, `SchemaField`
  and `SchemaAlternative` are now exported from `SchemaNode.ts`.
- `SchemaCodec.schema`, returning the schema the codec was built from.
- Guides: `examples/typed-api.md`, `examples/dsl.md`, `examples/codegen.md`.

### Changed

- **Breaking (types).** `SchemaCodec.encode`, `encodeToHex` and
  `encodeToRawBytes` no longer accept `RawBytes` in place of a value. Use
  `codec.raw.encode(...)` and friends instead. Allowing `RawBytes` at every node
  doubled the length of every type printed in an encode error, for a feature most
  values never use. The runtime is unchanged and still accepts `RawBytes`
  anywhere.
- **Breaking (types).** `encode()` now rejects values that do not fit the schema.
  This is the point of the release, but code that compiled against the old
  `unknown` signature may now need fixing — most often because an intermediate
  `const` widened a literal, which annotating with `Infer<typeof schema>` solves.
- **Breaking (types).** `SchemaNode`'s collections are `readonly`, so inline
  schemas keep their literal types. Code that mutated a `SchemaNode`'s `fields`,
  `alternatives` or `values` after construction no longer compiles.
- `Codec<T>` takes a second, optional type parameter: `Codec<T, TInput = T>`.
  Existing single-argument uses are unaffected.
- `DecodedNode` takes an optional type parameter: `DecodedNode<T = unknown>`.
  `stripMetadata` derives its return type from the node it is given rather than
  returning `unknown`.
- `SchemaCodec` is generic in its schema. A schema known only at runtime — parsed
  from JSON or from ASN.1 text — stays the wide `SchemaNode` union and every
  method keeps the `unknown` types it had before.
- `sideEffects` narrowed from `false` to the CLI entry point, which does run on
  import. The library itself stays tree-shakeable.
- `SchemaNode` moved to `src/schema/SchemaNode.ts`. It is still re-exported from
  `SchemaBuilder.ts` and from the package root.

### Removed

- **Breaking.** The `cli/generate-schema.ts` and `cli/generate-types.ts` scripts,
  which could only be run from a checkout with `npx tsx`. They are now the
  `schema` and `types` subcommands of the `asn1-per-ts` executable; from a
  checkout, run `npx tsx src/cli/main.ts <subcommand>`.

### Fixed

- The code generator emitted its type imports unconditionally, so a module
  generated with `--no-runtime` imported `SchemaRegistry` and `TypedCodec`
  without using them and failed to compile under `noUnusedLocals`.
- The CHOICE examples in `examples/encoding.md` and `examples/decoding.md`
  documented a `{ name: value }` shape the codecs stopped producing, with a hex
  string that threw when decoded. They now show `{ key, value }` with working
  hex.
