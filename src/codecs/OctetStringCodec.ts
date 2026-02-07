import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import {
  encodeConstrainedLength,
  decodeConstrainedLength,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export interface OctetStringConstraints {
  fixedSize?: number;
  minSize?: number;
  maxSize?: number;
  extensible?: boolean;
}

/**
 * PER unaligned OCTET STRING codec (X.691 §16).
 */
export class OctetStringCodec implements Codec<Uint8Array> {
  private readonly constraints: OctetStringConstraints;

  constructor(constraints?: OctetStringConstraints) {
    this.constraints = constraints ?? {};
  }

  encode(buffer: BitBuffer, value: Uint8Array): void {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;

    if (fixedSize !== undefined) {
      if (extensible) {
        if (value.length === fixedSize) {
          buffer.writeBit(0);
          buffer.writeOctets(value);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, value.length);
          buffer.writeOctets(value);
        }
      } else {
        if (value.length !== fixedSize) {
          throw new Error(`OCTET STRING: expected ${fixedSize} bytes, got ${value.length}`);
        }
        buffer.writeOctets(value);
      }
      return;
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        if (value.length >= minSize && value.length <= maxSize) {
          buffer.writeBit(0);
          encodeConstrainedLength(buffer, value.length, minSize, maxSize);
          buffer.writeOctets(value);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, value.length);
          buffer.writeOctets(value);
        }
      } else {
        if (value.length < minSize || value.length > maxSize) {
          throw new Error(`OCTET STRING length ${value.length} out of range [${minSize}, ${maxSize}]`);
        }
        encodeConstrainedLength(buffer, value.length, minSize, maxSize);
        buffer.writeOctets(value);
      }
      return;
    }

    // Unconstrained
    encodeUnconstrainedLength(buffer, value.length);
    buffer.writeOctets(value);
  }

  decode(buffer: BitBuffer): Uint8Array {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          return buffer.readOctets(fixedSize);
        }
        const len = decodeUnconstrainedLength(buffer);
        return buffer.readOctets(len);
      }
      return buffer.readOctets(fixedSize);
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          const len = decodeConstrainedLength(buffer, minSize, maxSize);
          return buffer.readOctets(len);
        }
        const len = decodeUnconstrainedLength(buffer);
        return buffer.readOctets(len);
      }
      const len = decodeConstrainedLength(buffer, minSize, maxSize);
      return buffer.readOctets(len);
    }

    const len = decodeUnconstrainedLength(buffer);
    return buffer.readOctets(len);
  }
}
