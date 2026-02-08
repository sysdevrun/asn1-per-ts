import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import type { DecodedNode } from './DecodedNode';
import {
  encodeConstrainedWholeNumber,
  decodeConstrainedWholeNumber,
  encodeNormallySmallNumber,
  decodeNormallySmallNumber,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export interface ChoiceAlternative {
  /** The name/tag of this alternative. */
  name: string;
  /** The codec for this alternative's value. */
  codec: Codec<unknown>;
}

export interface ChoiceOptions {
  /** Root alternatives in canonical tag order. */
  alternatives: readonly ChoiceAlternative[];
  /** Extension alternatives, in definition order. */
  extensionAlternatives?: readonly ChoiceAlternative[];
}

/** Value type for CHOICE: a discriminated object with a single key. */
export interface ChoiceValue {
  /** The name of the selected alternative. */
  key: string;
  /** The value of the selected alternative. */
  value: unknown;
}

/**
 * PER unaligned CHOICE codec (X.691 §22).
 * Encodes the index of the chosen alternative followed by its value.
 */
export class ChoiceCodec implements Codec<ChoiceValue> {
  private readonly rootAlts: readonly ChoiceAlternative[];
  private readonly extAlts: readonly ChoiceAlternative[];
  private readonly _extensible: boolean;
  private readonly rootNameIndex: Map<string, number>;
  private readonly extNameIndex: Map<string, number>;

  constructor(options: ChoiceOptions) {
    if (options.alternatives.length === 0) {
      throw new Error('CHOICE must have at least one alternative');
    }
    this.rootAlts = options.alternatives;
    this.extAlts = options.extensionAlternatives ?? [];
    // Extensible if extensionAlternatives was explicitly provided (even if empty)
    this._extensible = options.extensionAlternatives !== undefined;
    this.rootNameIndex = new Map(this.rootAlts.map((a, i) => [a.name, i]));
    this.extNameIndex = new Map(this.extAlts.map((a, i) => [a.name, i]));
  }

  get extensible(): boolean {
    return this._extensible;
  }

  encode(buffer: BitBuffer, value: ChoiceValue): void {
    const rootIdx = this.rootNameIndex.get(value.key);

    if (this.extensible) {
      if (rootIdx !== undefined) {
        buffer.writeBit(0);
        if (this.rootAlts.length > 1) {
          encodeConstrainedWholeNumber(buffer, rootIdx, 0, this.rootAlts.length - 1);
        }
        this.rootAlts[rootIdx].codec.encode(buffer, value.value);
      } else {
        const extIdx = this.extNameIndex.get(value.key);
        if (extIdx === undefined) {
          throw new Error(`Unknown CHOICE alternative: '${value.key}'`);
        }
        buffer.writeBit(1);
        encodeNormallySmallNumber(buffer, extIdx);
        // Encode as open type: encode to temp buffer, then write length + bytes
        const tmp = BitBuffer.alloc();
        this.extAlts[extIdx].codec.encode(tmp, value.value);
        const bytes = tmp.toUint8Array();
        encodeUnconstrainedLength(buffer, bytes.length);
        buffer.writeOctets(bytes);
      }
    } else {
      if (rootIdx === undefined) {
        throw new Error(`Unknown CHOICE alternative: '${value.key}'`);
      }
      if (this.rootAlts.length > 1) {
        encodeConstrainedWholeNumber(buffer, rootIdx, 0, this.rootAlts.length - 1);
      }
      this.rootAlts[rootIdx].codec.encode(buffer, value.value);
    }
  }

  decode(buffer: BitBuffer): ChoiceValue {
    if (this.extensible) {
      const extBit = buffer.readBit();
      if (extBit === 0) {
        const idx = this.rootAlts.length > 1
          ? decodeConstrainedWholeNumber(buffer, 0, this.rootAlts.length - 1)
          : 0;
        const alt = this.rootAlts[idx];
        return { key: alt.name, value: alt.codec.decode(buffer) };
      }
      const extIdx = decodeNormallySmallNumber(buffer);
      if (extIdx >= this.extAlts.length) {
        throw new Error(`Extension index ${extIdx} out of range for CHOICE`);
      }
      // Decode as open type
      const byteLen = decodeUnconstrainedLength(buffer);
      const bytes = buffer.readOctets(byteLen);
      const tmp = BitBuffer.from(bytes);
      const alt = this.extAlts[extIdx];
      return { key: alt.name, value: alt.codec.decode(tmp) };
    }

    const idx = this.rootAlts.length > 1
      ? decodeConstrainedWholeNumber(buffer, 0, this.rootAlts.length - 1)
      : 0;
    const alt = this.rootAlts[idx];
    return { key: alt.name, value: alt.codec.decode(buffer) };
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    const bitOffset = buffer.offset;

    if (this.extensible) {
      const extBit = buffer.readBit();
      if (extBit === 0) {
        const idx = this.rootAlts.length > 1
          ? decodeConstrainedWholeNumber(buffer, 0, this.rootAlts.length - 1)
          : 0;
        const alt = this.rootAlts[idx];
        const childNode = alt.codec.decodeWithMetadata(buffer);
        const bitLength = buffer.offset - bitOffset;
        return {
          value: { key: alt.name, value: childNode },
          meta: {
            bitOffset,
            bitLength,
            rawBytes: buffer.extractBits(bitOffset, bitLength),
            codec: this,
          },
        };
      }
      const extIdx = decodeNormallySmallNumber(buffer);
      if (extIdx >= this.extAlts.length) {
        throw new Error(`Extension index ${extIdx} out of range for CHOICE`);
      }
      // Decode as open type
      const byteLen = decodeUnconstrainedLength(buffer);
      const bytes = buffer.readOctets(byteLen);
      const tmp = BitBuffer.from(bytes);
      const alt = this.extAlts[extIdx];
      const childNode = alt.codec.decodeWithMetadata(tmp);
      const bitLength = buffer.offset - bitOffset;
      return {
        value: { key: alt.name, value: childNode },
        meta: {
          bitOffset,
          bitLength,
          rawBytes: buffer.extractBits(bitOffset, bitLength),
          codec: this,
        },
      };
    }

    const idx = this.rootAlts.length > 1
      ? decodeConstrainedWholeNumber(buffer, 0, this.rootAlts.length - 1)
      : 0;
    const alt = this.rootAlts[idx];
    const childNode = alt.codec.decodeWithMetadata(buffer);
    const bitLength = buffer.offset - bitOffset;
    return {
      value: { key: alt.name, value: childNode },
      meta: {
        bitOffset,
        bitLength,
        rawBytes: buffer.extractBits(bitOffset, bitLength),
        codec: this,
      },
    };
  }
}
