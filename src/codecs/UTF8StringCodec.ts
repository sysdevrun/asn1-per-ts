import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import type { DecodedNode } from './DecodedNode';
import { primitiveDecodeWithMetadata } from './DecodedNode';
import {
  constrainedWholeNumberBitCount,
  encodeConstrainedLength,
  decodeConstrainedLength,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export type CharStringType = 'IA5String' | 'VisibleString' | 'UTF8String';

export interface CharStringConstraints {
  /** The ASN.1 string type. */
  type: CharStringType;
  /** Permitted alphabet constraint (FROM("...")). */
  alphabet?: string;
  fixedSize?: number;
  minSize?: number;
  maxSize?: number;
  extensible?: boolean;
}

// Default alphabet ranges
const IA5_ALPHABET = Array.from({ length: 128 }, (_, i) => String.fromCharCode(i));
const VISIBLE_ALPHABET = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i));

/**
 * PER unaligned string codec for IA5String, VisibleString, and UTF8String.
 * Known-multiplier types (IA5, Visible) use per-character index encoding.
 * UTF8String is encoded as OCTET STRING of UTF-8 bytes.
 */
export class UTF8StringCodec implements Codec<string> {
  private readonly config: CharStringConstraints;
  private readonly effectiveAlphabetArray: string[];
  private readonly charToIndex: Map<string, number>;
  private readonly _bitsPerChar: number;
  private readonly isKnownMultiplier: boolean;

  constructor(constraints: CharStringConstraints) {
    this.config = constraints;
    this.isKnownMultiplier = constraints.type !== 'UTF8String';

    if (this.isKnownMultiplier) {
      if (constraints.alphabet) {
        this.effectiveAlphabetArray = [...constraints.alphabet].sort();
      } else if (constraints.type === 'IA5String') {
        this.effectiveAlphabetArray = IA5_ALPHABET;
      } else {
        this.effectiveAlphabetArray = VISIBLE_ALPHABET;
      }

      // Remove duplicates while preserving sorted order
      this.effectiveAlphabetArray = [...new Set(this.effectiveAlphabetArray)].sort();

      this.charToIndex = new Map(
        this.effectiveAlphabetArray.map((ch, i) => [ch, i])
      );

      const n = this.effectiveAlphabetArray.length;
      this._bitsPerChar = n <= 1 ? 0 : Math.ceil(Math.log2(n));
    } else {
      this.effectiveAlphabetArray = [];
      this.charToIndex = new Map();
      this._bitsPerChar = 8;
    }
  }

  /** Bits per character for known-multiplier types. */
  get bitsPerCharacter(): number {
    return this._bitsPerChar;
  }

  /** The canonically sorted effective permitted alphabet. */
  get effectiveAlphabet(): readonly string[] {
    return this.effectiveAlphabetArray;
  }

  encode(buffer: BitBuffer, value: string): void {
    if (!this.isKnownMultiplier) {
      this.encodeAsOctets(buffer, value);
      return;
    }
    this.encodeKnownMultiplier(buffer, value);
  }

  decode(buffer: BitBuffer): string {
    if (!this.isKnownMultiplier) {
      return this.decodeAsOctets(buffer);
    }
    return this.decodeKnownMultiplier(buffer);
  }

  private encodeKnownMultiplier(buffer: BitBuffer, value: string): void {
    const chars = [...value];
    const { fixedSize, minSize, maxSize, extensible } = this.config;

    // Validate characters
    for (const ch of chars) {
      if (!this.charToIndex.has(ch)) {
        throw new Error(`Character '${ch}' not in permitted alphabet`);
      }
    }

    const charLen = chars.length;

    if (fixedSize !== undefined) {
      if (extensible) {
        if (charLen === fixedSize) {
          buffer.writeBit(0);
          this.writeChars(buffer, chars);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, charLen);
          this.writeChars(buffer, chars);
        }
      } else {
        if (charLen !== fixedSize) {
          throw new Error(`String length ${charLen} does not match fixed size ${fixedSize}`);
        }
        this.writeChars(buffer, chars);
      }
      return;
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        if (charLen >= minSize && charLen <= maxSize) {
          buffer.writeBit(0);
          encodeConstrainedLength(buffer, charLen, minSize, maxSize);
          this.writeChars(buffer, chars);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, charLen);
          this.writeChars(buffer, chars);
        }
      } else {
        if (charLen < minSize || charLen > maxSize) {
          throw new Error(`String length ${charLen} out of range [${minSize}, ${maxSize}]`);
        }
        encodeConstrainedLength(buffer, charLen, minSize, maxSize);
        this.writeChars(buffer, chars);
      }
      return;
    }

    // Unconstrained length
    encodeUnconstrainedLength(buffer, charLen);
    this.writeChars(buffer, chars);
  }

  private decodeKnownMultiplier(buffer: BitBuffer): string {
    const { fixedSize, minSize, maxSize, extensible } = this.config;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          return this.readChars(buffer, fixedSize);
        }
        const len = decodeUnconstrainedLength(buffer);
        return this.readChars(buffer, len);
      }
      return this.readChars(buffer, fixedSize);
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        if (extBit === 0) {
          const len = decodeConstrainedLength(buffer, minSize, maxSize);
          return this.readChars(buffer, len);
        }
        const len = decodeUnconstrainedLength(buffer);
        return this.readChars(buffer, len);
      }
      const len = decodeConstrainedLength(buffer, minSize, maxSize);
      return this.readChars(buffer, len);
    }

    const len = decodeUnconstrainedLength(buffer);
    return this.readChars(buffer, len);
  }

  private writeChars(buffer: BitBuffer, chars: string[]): void {
    for (const ch of chars) {
      const idx = this.charToIndex.get(ch)!;
      if (this._bitsPerChar > 0) {
        buffer.writeBits(idx, this._bitsPerChar);
      }
    }
  }

  private readChars(buffer: BitBuffer, count: number): string {
    let result = '';
    for (let i = 0; i < count; i++) {
      const idx = this._bitsPerChar > 0 ? buffer.readBits(this._bitsPerChar) : 0;
      if (idx >= this.effectiveAlphabetArray.length) {
        throw new Error(`Character index ${idx} out of alphabet range`);
      }
      result += this.effectiveAlphabetArray[idx];
    }
    return result;
  }

  private encodeAsOctets(buffer: BitBuffer, value: string): void {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(value);
    const { fixedSize, minSize, maxSize, extensible } = this.config;

    if (fixedSize !== undefined) {
      if (extensible) {
        if (bytes.length === fixedSize) {
          buffer.writeBit(0);
          buffer.writeOctets(bytes);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, bytes.length);
          buffer.writeOctets(bytes);
        }
      } else {
        if (bytes.length !== fixedSize) {
          throw new Error(`UTF8String byte length ${bytes.length} does not match fixed size ${fixedSize}`);
        }
        buffer.writeOctets(bytes);
      }
      return;
    }

    if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        if (bytes.length >= minSize && bytes.length <= maxSize) {
          buffer.writeBit(0);
          encodeConstrainedLength(buffer, bytes.length, minSize, maxSize);
          buffer.writeOctets(bytes);
        } else {
          buffer.writeBit(1);
          encodeUnconstrainedLength(buffer, bytes.length);
          buffer.writeOctets(bytes);
        }
      } else {
        if (bytes.length < minSize || bytes.length > maxSize) {
          throw new Error(`UTF8String byte length ${bytes.length} out of range [${minSize}, ${maxSize}]`);
        }
        encodeConstrainedLength(buffer, bytes.length, minSize, maxSize);
        buffer.writeOctets(bytes);
      }
      return;
    }

    encodeUnconstrainedLength(buffer, bytes.length);
    buffer.writeOctets(bytes);
  }

  private decodeAsOctets(buffer: BitBuffer): string {
    const { fixedSize, minSize, maxSize, extensible } = this.config;
    let len: number;

    if (fixedSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        len = extBit === 0 ? fixedSize : decodeUnconstrainedLength(buffer);
      } else {
        len = fixedSize;
      }
    } else if (minSize !== undefined && maxSize !== undefined) {
      if (extensible) {
        const extBit = buffer.readBit();
        len = extBit === 0
          ? decodeConstrainedLength(buffer, minSize, maxSize)
          : decodeUnconstrainedLength(buffer);
      } else {
        len = decodeConstrainedLength(buffer, minSize, maxSize);
      }
    } else {
      len = decodeUnconstrainedLength(buffer);
    }

    const bytes = buffer.readOctets(len);
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    return primitiveDecodeWithMetadata(this, buffer);
  }
}
