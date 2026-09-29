import type { RawBytes } from '../RawBytes.js';
import type { Codec } from '../codecs/Codec.js';
import type { DecodedNode } from '../codecs/DecodedNode.js';
import type { BitStringValue } from '../codecs/BitStringCodec.js';
import type { SchemaNode } from './SchemaNode.js';

/**
 * Widens a value type so that {@link RawBytes} is accepted in place of any
 * node — the encoder writes those bits verbatim instead of calling the node's
 * codec.
 *
 * This is deliberately kept out of the default encode signatures: allowing
 * `RawBytes` at every position doubles the size of every type in an error
 * message, for a feature most values never use. Reach it through
 * {@link TypedCodec.raw} instead.
 */
export type RawInput<T> = RawBytes | RawInputValue<T>;

type RawInputValue<T> = T extends RawBytes
  ? T
  : T extends Uint8Array
    ? T
    : T extends BitStringValue
      ? T
      : T extends readonly (infer E)[]
        ? readonly RawInput<E>[]
        : T extends { key: infer K; value: infer V }
          ? { key: K; value: RawInput<V> }
          : T extends object
            ? { [P in keyof T]: RawInput<T[P]> }
            : T;

/** Encoding entry points that also accept pre-encoded {@link RawBytes}. */
export interface RawEncoder<TIn> {
  /** Encode a value to a Uint8Array, allowing RawBytes at any node. */
  encode(value: RawInput<TIn>): Uint8Array;
  /** Encode a value to a RawBytes with exact bit-length, allowing RawBytes at any node. */
  encodeToRawBytes(value: RawInput<TIn>): RawBytes;
  /** Encode a value to a hex string, allowing RawBytes at any node. */
  encodeToHex(value: RawInput<TIn>): string;
}

/**
 * The codec interface every front-end produces.
 *
 * The three ways of describing a type — an inline `SchemaNode` literal, the
 * `asn` builder DSL, and generated TypeScript — all compile down to a
 * {@link SchemaNode} and hand back this same interface. Only the way the type
 * arguments are computed differs.
 *
 * @typeParam TOut - What `decode()` returns.
 * @typeParam TIn - What `encode()` accepts.
 * @typeParam TNode - The tree `decodeWithMetadata()` returns.
 */
export interface TypedCodec<TOut, TIn = TOut, TNode = DecodedNode> {
  /** Encode a value to a Uint8Array. */
  encode(value: TIn): Uint8Array;
  /** Encode a value and return a RawBytes with exact bit-length. */
  encodeToRawBytes(value: TIn): RawBytes;
  /** Encode a value and return hex string. */
  encodeToHex(value: TIn): string;

  /** Decode a Uint8Array back to a value. */
  decode(data: Uint8Array): TOut;
  /** Decode a hex string back to a value. */
  decodeFromHex(hex: string): TOut;
  /** Decode a Uint8Array with full metadata tree. */
  decodeWithMetadata(data: Uint8Array): TNode;
  /** Decode a hex string with full metadata tree. */
  decodeFromHexWithMetadata(hex: string): TNode;

  /**
   * The same encoder, but accepting pre-encoded {@link RawBytes} in place of
   * any node:
   *
   * ```typescript
   * codec.raw.encodeToHex({ header, payload: preEncoded });
   * ```
   */
  readonly raw: RawEncoder<TIn>;

  /** The schema this codec was built from. */
  readonly schema: SchemaNode;
  /** The underlying built codec. */
  readonly codec: Codec<TOut, TIn>;
}
