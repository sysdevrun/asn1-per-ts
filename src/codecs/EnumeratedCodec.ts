import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import {
  encodeConstrainedWholeNumber,
  decodeConstrainedWholeNumber,
  encodeNormallySmallNumber,
  decodeNormallySmallNumber,
} from '../helpers';

export interface EnumeratedOptions {
  /** Root enumeration values, in definition order. */
  values: readonly string[];
  /** Extension enumeration values (after "..."), in definition order. */
  extensionValues?: readonly string[];
}

/**
 * PER unaligned Enumerated codec (X.691 §13).
 * Root values are encoded as constrained integers over their indices.
 * Extension values use normally-small-non-negative-whole-number.
 */
export class EnumeratedCodec implements Codec<string> {
  private readonly rootValues: readonly string[];
  private readonly extValues: readonly string[];
  private readonly rootIndexMap: Map<string, number>;
  private readonly extIndexMap: Map<string, number>;

  constructor(options: EnumeratedOptions) {
    if (options.values.length === 0) {
      throw new Error('Enumerated type must have at least one root value');
    }
    this.rootValues = options.values;
    this.extValues = options.extensionValues ?? [];
    this.rootIndexMap = new Map(options.values.map((v, i) => [v, i]));
    this.extIndexMap = new Map(this.extValues.map((v, i) => [v, i]));
  }

  get extensible(): boolean {
    return this.extValues.length > 0;
  }

  encode(buffer: BitBuffer, value: string): void {
    const rootIdx = this.rootIndexMap.get(value);

    if (this.extensible) {
      if (rootIdx !== undefined) {
        buffer.writeBit(0);
        encodeConstrainedWholeNumber(buffer, rootIdx, 0, this.rootValues.length - 1);
      } else {
        const extIdx = this.extIndexMap.get(value);
        if (extIdx === undefined) {
          throw new Error(`Unknown enumerated value: '${value}'`);
        }
        buffer.writeBit(1);
        encodeNormallySmallNumber(buffer, extIdx);
      }
    } else {
      if (rootIdx === undefined) {
        throw new Error(`Unknown enumerated value: '${value}'`);
      }
      encodeConstrainedWholeNumber(buffer, rootIdx, 0, this.rootValues.length - 1);
    }
  }

  decode(buffer: BitBuffer): string {
    if (this.extensible) {
      const extBit = buffer.readBit();
      if (extBit === 0) {
        const idx = decodeConstrainedWholeNumber(buffer, 0, this.rootValues.length - 1);
        return this.rootValues[idx];
      }
      const idx = decodeNormallySmallNumber(buffer);
      if (idx >= this.extValues.length) {
        throw new Error(`Extension index ${idx} out of range for enumerated type`);
      }
      return this.extValues[idx];
    }

    const idx = decodeConstrainedWholeNumber(buffer, 0, this.rootValues.length - 1);
    return this.rootValues[idx];
  }
}
