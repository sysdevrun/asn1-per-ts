import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import {
  encodeConstrainedLength,
  decodeConstrainedLength,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export interface BitStringValue {
  /** Raw bytes containing the bits (MSB-first within each byte). */
  data: Uint8Array;
  /** Actual number of valid bits. */
  bitLength: number;
}

export interface BitStringConstraints {
  fixedSize?: number;
  minSize?: number;
  maxSize?: number;
  extensible?: boolean;
}

/**
 * PER unaligned BIT STRING codec (X.691 §15).
 */
export class BitStringCodec implements Codec<BitStringValue> {
  private readonly constraints: BitStringConstraints;

  constructor(constraints?: BitStringConstraints) {
    this.constraints = constraints ?? {};
  }

  encode(buffer: BitBuffer, value: BitStringValue): void {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;

    if (fixedSize !== undefined) {
      if (extensible) {
        if (value.bitLength === fixedSize) {
          buffer.writeBit(0);
          this.writeBits(buffer, value, fixedSize);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, value.bitLength);
          this.writeBits(buffer, value, value.bitLength);
        }
      } else {
        if (value.bitLength !== fixedSize) {
          throw new Error(`BIT STRING: expected ${fixedSize} bits, got ${value.bitLength}`);
        }
        this.writeBits(buffer, value, fixedSize);
      }
      return;
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        if (value.bitLength >= minSize && value.bitLength <= maxSize) {
          buffer.writeBit(0);
          encodeConstrainedLength(buffer, value.bitLength, minSize, maxSize);
          this.writeBits(buffer, value, value.bitLength);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, value.bitLength);
          this.writeBits(buffer, value, value.bitLength);
        }
      } else {
        if (value.bitLength < minSize || value.bitLength > maxSize) {
          throw new Error(`BIT STRING length ${value.bitLength} out of range [${minSize}, ${maxSize}]`);
        }
        encodeConstrainedLength(buffer, value.bitLength, minSize, maxSize);
        this.writeBits(buffer, value, value.bitLength);
      }
      return;
    }

    // Unconstrained
    encodeUnconstrainedLength(buffer, value.bitLength);
    this.writeBits(buffer, value, value.bitLength);
  }

  decode(buffer: BitBuffer): BitStringValue {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          return this.readBitsValue(buffer, fixedSize);
        }
        const len = decodeUnconstrainedLength(buffer);
        return this.readBitsValue(buffer, len);
      }
      return this.readBitsValue(buffer, fixedSize);
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          const len = decodeConstrainedLength(buffer, minSize, maxSize);
          return this.readBitsValue(buffer, len);
        }
        const len = decodeUnconstrainedLength(buffer);
        return this.readBitsValue(buffer, len);
      }
      const len = decodeConstrainedLength(buffer, minSize, maxSize);
      return this.readBitsValue(buffer, len);
    }

    const len = decodeUnconstrainedLength(buffer);
    return this.readBitsValue(buffer, len);
  }

  private writeBits(buffer: BitBuffer, value: BitStringValue, count: number): void {
    const src = BitBuffer.from(value.data, value.bitLength);
    for (let i = 0; i < count; i++) {
      buffer.writeBit(src.readBit());
    }
  }

  private readBitsValue(buffer: BitBuffer, bitLength: number): BitStringValue {
    const byteLen = Math.ceil(bitLength / 8);
    const data = new Uint8Array(byteLen);
    const tmp = BitBuffer.alloc(byteLen);
    for (let i = 0; i < bitLength; i++) {
      tmp.writeBit(buffer.readBit());
    }
    const arr = tmp.toUint8Array();
    data.set(arr);
    return { data, bitLength };
  }
}
