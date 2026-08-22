/**
 * Compile-time mapping from a {@link SchemaNode} to the TypeScript types it
 * encodes and decodes.
 *
 * These are pure type-level utilities: nothing here exists at runtime and no
 * validation is performed. They work by reading the *literal* type of a
 * schema, so the schema must keep its literal types. Use
 * {@link ./SchemaCodec.js#defineSchema | defineSchema},
 * {@link ./SchemaCodec.js#createCodec | createCodec}, `new SchemaCodec(...)`
 * or a plain `as const` object to get that.
 *
 * When the schema is only known as the wide `SchemaNode` union — for example a
 * value parsed from JSON at runtime — every helper here degrades to `unknown`,
 * which is exactly what the untyped API returned before.
 */
import type { RawBytes } from '../RawBytes.js';
import type { BitStringValue } from '../codecs/BitStringCodec.js';
import type { DecodedNode } from '../codecs/DecodedNode.js';
import type { SchemaAlternative, SchemaField, SchemaNode, SchemaRegistry } from './SchemaNode.js';
import type { Simplify } from '../typeUtils.js';


/** Number of nested `$ref` expansions performed before bailing out to `unknown`. */
export type DefaultRefDepth = 12;

/** Type-level decrement, used to bound `$ref` expansion of recursive schemas. */
type Decrement = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/** True when `S` has not been narrowed below the full `SchemaNode` union. */
type IsWideSchema<S> = [SchemaNode] extends [S] ? true : false;

/**
 * A field is an optional property of the decoded object when it is declared
 * OPTIONAL *and* carries no DEFAULT: `decode()` substitutes the DEFAULT value
 * when the field is absent from the encoding, so DEFAULT fields are always
 * present in the decoded object.
 */
type DecodesToOptionalProperty<F> = F extends { defaultValue: undefined }
  ? IsDeclaredOptional<F>
  : F extends { defaultValue: unknown }
    ? false
    : IsDeclaredOptional<F>;

type IsDeclaredOptional<F> = F extends { optional: true } ? true : false;

/** A field may be omitted when encoding if it is OPTIONAL or has a DEFAULT. */
type IsOmittableOnEncode<F> = F extends { defaultValue: undefined }
  ? IsDeclaredOptional<F>
  : F extends { defaultValue: unknown }
    ? true
    : IsDeclaredOptional<F>;

/* -------------------------------------------------------------------------
 * Infer — the type `decode()` produces
 * ---------------------------------------------------------------------- */

/**
 * The TypeScript type produced by decoding `S`.
 *
 * @typeParam S - The schema, with its literal type preserved.
 * @typeParam R - Registry used to resolve `$ref` nodes.
 * @typeParam D - Remaining `$ref` expansions before the result becomes `unknown`.
 */
export type Infer<
  S,
  R extends SchemaRegistry = Record<never, never>,
  D extends number = DefaultRefDepth,
> = IsWideSchema<S> extends true ? unknown : InferValue<S, R, D>;

type InferValue<S, R extends SchemaRegistry, D extends number> = [D] extends [never]
  ? unknown
  : S extends { type: 'BOOLEAN' }
    ? boolean
    : S extends { type: 'NULL' }
      ? null
      : S extends { type: 'INTEGER' }
        ? number
        : S extends { type: 'ENUMERATED' }
          ? InferEnumerated<S>
          : S extends { type: 'BIT STRING' }
            ? BitStringValue
            : S extends { type: 'OCTET STRING' }
              ? Uint8Array
              : S extends { type: 'OBJECT IDENTIFIER' }
                ? string
                : S extends { type: 'IA5String' | 'VisibleString' | 'UTF8String' }
                  ? string
                  : S extends { type: 'SEQUENCE OF'; item: infer I }
                    ? Infer<I, R, D>[]
                    : S extends { type: 'CHOICE' }
                      ? InferChoice<S, R, D>
                      : S extends { type: 'SEQUENCE' }
                        ? InferSequence<S, R, D>
                        : S extends { type: '$ref'; ref: infer N }
                          ? InferRef<N, R, D>
                          : unknown;

type InferEnumerated<S> = S extends { values: readonly (infer V extends string)[] }
  ? S extends { extensionValues: readonly (infer E extends string)[] }
    ? V | E
    : V
  : string;

type InferRef<N, R extends SchemaRegistry, D extends number> = N extends keyof R
  ? Infer<R[N], R, Decrement[D]>
  : unknown;

type InferChoice<S, R extends SchemaRegistry, D extends number> =
  | (S extends { alternatives: infer A extends readonly SchemaAlternative[] }
      ? InferAlternatives<A, R, D>
      : never)
  | (S extends { extensionAlternatives: infer E extends readonly SchemaAlternative[] }
      ? InferAlternatives<E, R, D>
      : never);

type InferAlternatives<A extends readonly SchemaAlternative[], R extends SchemaRegistry, D extends number> = {
  [K in keyof A]: { key: A[K]['name']; value: Infer<A[K]['schema'], R, D> };
}[number];

type InferSequence<S, R extends SchemaRegistry, D extends number> = Simplify<
  (S extends { fields: infer F extends readonly SchemaField[] } ? InferRootFields<F, R, D> : unknown) &
    (S extends { extensionFields: infer E extends readonly SchemaField[] }
      ? InferExtensionFields<E, R, D>
      : unknown)
>;

type InferRootFields<F extends readonly SchemaField[], R extends SchemaRegistry, D extends number> = {
  [K in F[number] as DecodesToOptionalProperty<K> extends true ? never : K['name']]: Infer<K['schema'], R, D>;
} & {
  [K in F[number] as DecodesToOptionalProperty<K> extends true ? K['name'] : never]?: Infer<K['schema'], R, D>;
};

/** Extension additions are absent whenever the peer did not send them. */
type InferExtensionFields<F extends readonly SchemaField[], R extends SchemaRegistry, D extends number> = {
  [K in F[number] as K['name']]?: Infer<K['schema'], R, D>;
};

/* -------------------------------------------------------------------------
 * InferInput — the type `encode()` accepts
 * ---------------------------------------------------------------------- */

/**
 * The TypeScript type accepted when encoding `S`.
 *
 * It differs from {@link Infer} in two ways:
 *
 * - DEFAULT fields may be omitted (the encoder writes a presence bit of `0`).
 * - Any node may instead be a {@link RawBytes}, which is written to the buffer
 *   verbatim rather than through the field's codec.
 */
export type InferInput<
  S,
  R extends SchemaRegistry = Record<never, never>,
  D extends number = DefaultRefDepth,
> = IsWideSchema<S> extends true ? unknown : RawBytes | InferInputValue<S, R, D>;

type InferInputValue<S, R extends SchemaRegistry, D extends number> = [D] extends [never]
  ? unknown
  : S extends { type: 'SEQUENCE OF'; item: infer I }
    ? readonly InferInput<I, R, D>[]
    : S extends { type: 'CHOICE' }
      ? InferInputChoice<S, R, D>
      : S extends { type: 'SEQUENCE' }
        ? InferInputSequence<S, R, D>
        : S extends { type: '$ref'; ref: infer N }
          ? N extends keyof R
            ? InferInput<R[N], R, Decrement[D]>
            : unknown
          : InferValue<S, R, D>;

type InferInputChoice<S, R extends SchemaRegistry, D extends number> =
  | (S extends { alternatives: infer A extends readonly SchemaAlternative[] }
      ? InferInputAlternatives<A, R, D>
      : never)
  | (S extends { extensionAlternatives: infer E extends readonly SchemaAlternative[] }
      ? InferInputAlternatives<E, R, D>
      : never);

type InferInputAlternatives<
  A extends readonly SchemaAlternative[],
  R extends SchemaRegistry,
  D extends number,
> = {
  [K in keyof A]: { key: A[K]['name']; value: InferInput<A[K]['schema'], R, D> };
}[number];

type InferInputSequence<S, R extends SchemaRegistry, D extends number> = Simplify<
  (S extends { fields: infer F extends readonly SchemaField[] } ? InferInputRootFields<F, R, D> : unknown) &
    (S extends { extensionFields: infer E extends readonly SchemaField[] }
      ? InferInputExtensionFields<E, R, D>
      : unknown)
>;

type InferInputRootFields<F extends readonly SchemaField[], R extends SchemaRegistry, D extends number> = {
  [K in F[number] as IsOmittableOnEncode<K> extends true ? never : K['name']]: InferInput<K['schema'], R, D>;
} & {
  [K in F[number] as IsOmittableOnEncode<K> extends true ? K['name'] : never]?: InferInput<K['schema'], R, D>;
};

type InferInputExtensionFields<
  F extends readonly SchemaField[],
  R extends SchemaRegistry,
  D extends number,
> = {
  [K in F[number] as K['name']]?: InferInput<K['schema'], R, D>;
};

/* -------------------------------------------------------------------------
 * InferMetadata — the type `decodeWithMetadata()` produces
 * ---------------------------------------------------------------------- */

/**
 * The {@link DecodedNode} tree produced by decoding `S` with metadata.
 *
 * Unlike {@link Infer}, every field of a SEQUENCE is present in the tree —
 * absent OPTIONAL fields appear as a node whose `value` is `undefined`.
 */
export type InferMetadata<
  S,
  R extends SchemaRegistry = Record<never, never>,
  D extends number = DefaultRefDepth,
> = IsWideSchema<S> extends true ? DecodedNode : InferMetadataValue<S, R, D>;

type InferMetadataValue<S, R extends SchemaRegistry, D extends number> = [D] extends [never]
  ? DecodedNode
  : S extends { type: 'SEQUENCE OF'; item: infer I }
    ? DecodedNode<InferMetadata<I, R, D>[]>
    : S extends { type: 'CHOICE' }
      ? DecodedNode<InferMetadataChoice<S, R, D>>
      : S extends { type: 'SEQUENCE' }
        ? DecodedNode<InferMetadataSequence<S, R, D>>
        : S extends { type: '$ref'; ref: infer N }
          ? N extends keyof R
            ? InferMetadata<R[N], R, Decrement[D]>
            : DecodedNode
          : DecodedNode<InferValue<S, R, D>>;

type InferMetadataChoice<S, R extends SchemaRegistry, D extends number> =
  | (S extends { alternatives: infer A extends readonly SchemaAlternative[] }
      ? InferMetadataAlternatives<A, R, D>
      : never)
  | (S extends { extensionAlternatives: infer E extends readonly SchemaAlternative[] }
      ? InferMetadataAlternatives<E, R, D>
      : never);

type InferMetadataAlternatives<
  A extends readonly SchemaAlternative[],
  R extends SchemaRegistry,
  D extends number,
> = {
  [K in keyof A]: { key: A[K]['name']; value: InferMetadata<A[K]['schema'], R, D> };
}[number];

type InferMetadataSequence<S, R extends SchemaRegistry, D extends number> = Simplify<
  (S extends { fields: infer F extends readonly SchemaField[] }
    ? { [K in F[number] as K['name']]: InferMetadataField<K, R, D> }
    : unknown) &
    (S extends { extensionFields: infer E extends readonly SchemaField[] }
      ? { [K in E[number] as K['name']]: MaybeAbsentNode<InferMetadata<K['schema'], R, D>> }
      : unknown)
>;

type InferMetadataField<K extends SchemaField, R extends SchemaRegistry, D extends number> =
  DecodesToOptionalProperty<K> extends true
    ? MaybeAbsentNode<InferMetadata<K['schema'], R, D>>
    : InferMetadata<K['schema'], R, D>;

/** Widens a node's `value` with `undefined`, for fields that may be absent. */
type MaybeAbsentNode<N> = N extends DecodedNode<infer V> ? DecodedNode<V | undefined> : N;
