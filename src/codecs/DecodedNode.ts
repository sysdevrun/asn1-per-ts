import type { BitBuffer } from '../BitBuffer';
import type { Codec } from './Codec';

/** Metadata attached to every decoded node. */
export interface FieldMeta {
  /** Start bit position in the source BitBuffer. */
  bitOffset: number;
  /** Number of bits consumed by this value's encoding. */
  bitLength: number;
  /**
   * Raw bytes of this value's encoding, extracted from the source buffer.
   * Bits are left-aligned in the first byte; trailing bits in the last
   * byte are zero-padded.
   */
  rawBytes: Uint8Array;
  /** The codec instance that decoded this node. */
  codec: Codec<unknown>;
  /** Whether the schema declared this field OPTIONAL. */
  optional?: boolean;
  /** Whether this field was actually present in the encoding. */
  present?: boolean;
  /** Whether the DEFAULT value was used (field not explicitly encoded). */
  isDefault?: boolean;
  /** Whether this field is an extension addition. */
  isExtension?: boolean;
}

/** A decoded value wrapped with encoding metadata. */
export interface DecodedNode {
  /**
   * The decoded value. Its shape depends on the codec:
   *
   * - Primitive codecs (Boolean, Integer, Enumerated, BitString,
   *   OctetString, UTF8String, ObjectIdentifier, Null):
   *   The raw JS value (boolean, number, string, Uint8Array, null, etc.)
   *
   * - SequenceCodec:
   *   Record<string, DecodedNode> — each field is a wrapped node.
   *
   * - SequenceOfCodec:
   *   DecodedNode[] — each array item is a wrapped node.
   *
   * - ChoiceCodec:
   *   { key: string; value: DecodedNode } — the selected alternative
   *   is a wrapped node.
   */
  value: unknown;
  meta: FieldMeta;
}

/**
 * Helper for primitive codecs: captures offset before/after decode
 * and returns a DecodedNode with metadata.
 */
export function primitiveDecodeWithMetadata(
  codec: Codec<unknown>,
  buffer: BitBuffer,
): DecodedNode {
  const bitOffset = buffer.offset;
  const value = codec.decode(buffer);
  const bitLength = buffer.offset - bitOffset;
  return {
    value,
    meta: {
      bitOffset,
      bitLength,
      rawBytes: buffer.extractBits(bitOffset, bitLength),
      codec,
    },
  };
}
