import { BitBuffer } from '../BitBuffer.js';
import type { DecodedNode } from './DecodedNode.js';

/**
 * Base interface for all PER unaligned codecs.
 *
 * @template T The TypeScript type this codec decodes to.
 * @template TInput The TypeScript type this codec accepts when encoding.
 * Defaults to `T`; the schema API widens it so that DEFAULT fields may be
 * omitted and any node may be given as pre-encoded {@link ../RawBytes.js#RawBytes}.
 */
export interface Codec<T, TInput = T> {
  /** Encode a value into the bit buffer. Throws if value violates constraints. */
  encode(buffer: BitBuffer, value: TInput): void;

  /** Decode a value from the bit buffer at its current offset. */
  decode(buffer: BitBuffer): T;

  /** Decode a value with full metadata (bit positions, raw bytes, codec info). */
  decodeWithMetadata(buffer: BitBuffer): DecodedNode;
}
