import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';

/**
 * PER unaligned Boolean codec (X.691 §11).
 * Encodes as a single bit: 0 = false, 1 = true.
 */
export class BooleanCodec implements Codec<boolean> {
  encode(buffer: BitBuffer, value: boolean): void {
    buffer.writeBit(value ? 1 : 0);
  }

  decode(buffer: BitBuffer): boolean {
    return buffer.readBit() === 1;
  }
}
