import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import type { DecodedNode } from './DecodedNode';
import {
  encodeConstrainedLength,
  decodeConstrainedLength,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export interface SequenceOfConstraints<T = unknown> {
  /** Codec for each element in the sequence. */
  itemCodec: Codec<T>;
  fixedSize?: number;
  minSize?: number;
  maxSize?: number;
  extensible?: boolean;
}

/**
 * PER unaligned SEQUENCE OF codec (X.691 §19).
 * Encodes a length determinant followed by repeated element encodings.
 */
export class SequenceOfCodec<T = unknown> implements Codec<T[]> {
  private readonly itemCodec: Codec<T>;
  private readonly constraints: Omit<SequenceOfConstraints<T>, 'itemCodec'>;

  constructor(options: SequenceOfConstraints<T>) {
    this.itemCodec = options.itemCodec;
    this.constraints = {
      fixedSize: options.fixedSize,
      minSize: options.minSize,
      maxSize: options.maxSize,
      extensible: options.extensible,
    };
  }

  encode(buffer: BitBuffer, value: T[]): void {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;
    const count = value.length;

    if (fixedSize !== undefined) {
      if (extensible) {
        if (count === fixedSize) {
          buffer.writeBit(0);
          this.encodeItems(buffer, value);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, count);
          this.encodeItems(buffer, value);
        }
      } else {
        if (count !== fixedSize) {
          throw new Error(`SEQUENCE OF: expected ${fixedSize} items, got ${count}`);
        }
        this.encodeItems(buffer, value);
      }
      return;
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        if (count >= minSize && count <= maxSize) {
          buffer.writeBit(0);
          encodeConstrainedLength(buffer, count, minSize, maxSize);
          this.encodeItems(buffer, value);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, count);
          this.encodeItems(buffer, value);
        }
      } else {
        if (count < minSize || count > maxSize) {
          throw new Error(`SEQUENCE OF: count ${count} out of range [${minSize}, ${maxSize}]`);
        }
        encodeConstrainedLength(buffer, count, minSize, maxSize);
        this.encodeItems(buffer, value);
      }
      return;
    }

    // Unconstrained
    encodeUnconstrainedLength(buffer, count);
    this.encodeItems(buffer, value);
  }

  decode(buffer: BitBuffer): T[] {
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          return this.decodeItems(buffer, fixedSize);
        }
        const count = decodeUnconstrainedLength(buffer);
        return this.decodeItems(buffer, count);
      }
      return this.decodeItems(buffer, fixedSize);
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          const count = decodeConstrainedLength(buffer, minSize, maxSize);
          return this.decodeItems(buffer, count);
        }
        const count = decodeUnconstrainedLength(buffer);
        return this.decodeItems(buffer, count);
      }
      const count = decodeConstrainedLength(buffer, minSize, maxSize);
      return this.decodeItems(buffer, count);
    }

    const count = decodeUnconstrainedLength(buffer);
    return this.decodeItems(buffer, count);
  }

  private encodeItems(buffer: BitBuffer, items: T[]): void {
    for (const item of items) {
      this.itemCodec.encode(buffer, item);
    }
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    const bitOffset = buffer.offset;
    const { fixedSize, minSize, maxSize, extensible } = this.constraints;
    let count: number;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          count = fixedSize;
        } else {
          count = decodeUnconstrainedLength(buffer);
        }
      } else {
        count = fixedSize;
      }
    } else if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          count = decodeConstrainedLength(buffer, minSize, maxSize);
        } else {
          count = decodeUnconstrainedLength(buffer);
        }
      } else {
        count = decodeConstrainedLength(buffer, minSize, maxSize);
      }
    } else {
      count = decodeUnconstrainedLength(buffer);
    }

    const items: DecodedNode[] = [];
    for (let i = 0; i < count; i++) {
      items.push(this.itemCodec.decodeWithMetadata(buffer));
    }

    const bitLength = buffer.offset - bitOffset;
    return {
      value: items,
      meta: {
        bitOffset,
        bitLength,
        rawBytes: buffer.extractBits(bitOffset, bitLength),
        codec: this,
      },
    };
  }

  private decodeItems(buffer: BitBuffer, count: number): T[] {
    const result: T[] = [];
    for (let i = 0; i < count; i++) {
      result.push(this.itemCodec.decode(buffer));
    }
    return result;
  }
}
