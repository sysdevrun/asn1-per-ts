import type { DecodedNode } from '../codecs/DecodedNode.js';
import type { SchemaNode } from '../schema/SchemaNode.js';

declare const OUT: unique symbol;
declare const IN: unique symbol;
declare const NODE: unique symbol;

/**
 * A schema built with the `asn` DSL.
 *
 * The TypeScript types travel in this value's type parameters rather than
 * being recomputed from a literal, so nothing is lost when a schema is stored
 * in a plain `const`, passed to a function, or reused across modules.
 *
 * @typeParam TOut - What decoding this schema produces.
 * @typeParam TIn - What encoding this schema accepts.
 * @typeParam TNode - The metadata tree decoding this schema produces.
 */
export interface Schema<TOut, TIn = TOut, TNode = DecodedNode<TOut>> {
  /** The interchange representation — the same `SchemaNode` the parser emits. */
  readonly node: SchemaNode;

  /** Mark this field OPTIONAL. Only meaningful inside {@link sequence}. */
  optional(): OptionalSchema<TOut, TIn, TNode>;

  /**
   * Give this field a DEFAULT value. Only meaningful inside {@link sequence}.
   *
   * The field may then be omitted when encoding, and is always present after
   * decoding — the decoder substitutes the default.
   */
  default(value: TOut): DefaultSchema<TOut, TIn, TNode>;

  /** @internal phantom — never present at runtime. */
  readonly [OUT]?: TOut;
  /** @internal phantom — never present at runtime. */
  readonly [IN]?: TIn;
  /** @internal phantom — never present at runtime. */
  readonly [NODE]?: TNode;
}

/** A schema marked OPTIONAL for use as a SEQUENCE field. */
export interface OptionalSchema<TOut, TIn = TOut, TNode = DecodedNode<TOut>>
  extends Schema<TOut, TIn, TNode> {
  readonly __optional: true;
}

/** A schema carrying a DEFAULT value for use as a SEQUENCE field. */
export interface DefaultSchema<TOut, TIn = TOut, TNode = DecodedNode<TOut>>
  extends Schema<TOut, TIn, TNode> {
  readonly __default: true;
  readonly __defaultValue: TOut;
}

/** Any schema, whatever it encodes. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnySchema = Schema<any, any, any>;

/**
 * A schema for `T`, whatever metadata-tree type it computes.
 *
 * Recursive schemas do not need an annotation — `asn.ref<Tree>('Tree')` already
 * supplies the type, and the surrounding schema infers from it. Use this when
 * you want the annotation anyway, as a check that the schema really does
 * describe `T`; the cost is that `decodeWithMetadata` on that schema is no
 * longer typed.
 *
 * ```typescript
 * const Tree: SchemaFor<Tree> = asn.sequence({ ... });
 * ```
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SchemaFor<T, TIn = T> = Schema<T, TIn, any>;

/** The type decoding `S` produces. */
export type TypeOf<S> = S extends Schema<infer T, infer _I, infer _N> ? T : never;
/** The type encoding `S` accepts. */
export type InputOf<S> = S extends Schema<infer _T, infer I, infer _N> ? I : never;
/** The metadata tree decoding `S` produces. */
export type NodeOf<S> = S extends Schema<infer _T, infer _I, infer N> ? N : never;

/** Build a Schema value. Internal to the DSL. */
export function makeSchema<TOut, TIn = TOut, TNode = DecodedNode<TOut>>(
  node: SchemaNode,
): Schema<TOut, TIn, TNode> {
  const self: Schema<TOut, TIn, TNode> = {
    node,
    optional() {
      return { ...self, __optional: true } as OptionalSchema<TOut, TIn, TNode>;
    },
    default(value: TOut) {
      return {
        ...self,
        __default: true,
        __defaultValue: value,
      } as unknown as DefaultSchema<TOut, TIn, TNode>;
    },
  };
  return self;
}
