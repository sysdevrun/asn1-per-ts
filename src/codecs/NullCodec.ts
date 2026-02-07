import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';

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
}
