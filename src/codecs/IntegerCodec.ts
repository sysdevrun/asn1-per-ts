import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import {
  constrainedWholeNumberBitCount,
  encodeConstrainedWholeNumber,
  decodeConstrainedWholeNumber,
  encodeSemiConstrainedWholeNumber,
  decodeSemiConstrainedWholeNumber,
  encodeUnconstrainedWholeNumber,
  decodeUnconstrainedWholeNumber,
} from '../helpers';

export interface IntegerConstraints {
  /** Lower bound (inclusive). Omit for semi-constrained or unconstrained. */
  min?: number;
  /** Upper bound (inclusive). Omit for semi-constrained or unconstrained. */
  max?: number;
  /** Whether the constraint has an extension marker (...). */
  extensible?: boolean;
}

export type IntegerConstraintType = 'constrained' | 'semi-constrained' | 'unconstrained';

/**
 * PER unaligned Integer codec (X.691 §12).
 * Supports constrained, semi-constrained, and unconstrained integers.
 */
export class IntegerCodec implements Codec<number> {
  private readonly constraints: IntegerConstraints;

  constructor(constraints?: IntegerConstraints) {
    this.constraints = constraints ?? {};
  }

  get constraintType(): IntegerConstraintType {
    const { min, max } = this.constraints;
    if (min !== undefined && max !== undefined) return 'constrained';
    if (min !== undefined) return 'semi-constrained';
    return 'unconstrained';
  }

  /** Number of bits for a constrained integer, or undefined if not fixed-width. */
  get bitWidth(): number | undefined {
    if (this.constraintType !== 'constrained') return undefined;
    return constrainedWholeNumberBitCount(this.constraints.min!, this.constraints.max!);
  }

  encode(buffer: BitBuffer, value: number): void {
    const { min, max, extensible } = this.constraints;

    if (extensible && min !== undefined && max !== undefined) {
      if (value >= min && value <= max) {
        buffer.writeBit(0);
        encodeConstrainedWholeNumber(buffer, value, min, max);
      } else {
        buffer.writeBit(1);
        encodeUnconstrainedWholeNumber(buffer, value);
      }
      return;
    }

    if (min !== undefined && max !== undefined) {
      encodeConstrainedWholeNumber(buffer, value, min, max);
    } else if (min !== undefined) {
      encodeSemiConstrainedWholeNumber(buffer, value, min);
    } else {
      encodeUnconstrainedWholeNumber(buffer, value);
    }
  }

  decode(buffer: BitBuffer): number {
    const { min, max, extensible } = this.constraints;

    if (extensible && min !== undefined && max !== undefined) {
      const extBit = buffer.readBit();
      if (extBit === 0) {
        return decodeConstrainedWholeNumber(buffer, min, max);
      }
      return decodeUnconstrainedWholeNumber(buffer);
    }

    if (min !== undefined && max !== undefined) {
      return decodeConstrainedWholeNumber(buffer, min, max);
    } else if (min !== undefined) {
      return decodeSemiConstrainedWholeNumber(buffer, min);
    } else {
      return decodeUnconstrainedWholeNumber(buffer);
    }
  }
}
