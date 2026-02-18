import { BitBuffer } from '../BitBuffer.js';
import { Codec } from './Codec.js';
import type { DecodedNode } from './DecodedNode.js';
import { primitiveDecodeWithMetadata } from './DecodedNode.js';

/**
 * PER unaligned Null codec (X.691 §14).
 * Zero bits encoded or decoded.
 */
export class NullCodec implements Codec<null> {
  encode(_buffer: BitBuffer, _value: null): void {
    // No bits written
  }

  decode(_buffer: BitBuffer): null {
    return null;
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    return primitiveDecodeWithMetadata(this, buffer);
  }
}
