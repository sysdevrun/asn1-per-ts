import { BitBuffer } from '../BitBuffer';

/**
 * Base interface for all PER unaligned codecs.
 * @template T The TypeScript type this codec encodes/decodes.
 */
export interface Codec<T> {
  /** Encode a value into the bit buffer. Throws if value violates constraints. */
  encode(buffer: BitBuffer, value: T): void;

  /** Decode a value from the bit buffer at its current offset. */
  decode(buffer: BitBuffer): T;
}
