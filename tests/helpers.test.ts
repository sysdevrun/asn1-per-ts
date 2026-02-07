import { BitBuffer } from '../src/BitBuffer';
import {
  constrainedWholeNumberBitCount,
  encodeConstrainedWholeNumber,
  decodeConstrainedWholeNumber,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
  encodeConstrainedLength,
  decodeConstrainedLength,
  encodeNormallySmallNumber,
  decodeNormallySmallNumber,
  encodeSemiConstrainedWholeNumber,
  decodeSemiConstrainedWholeNumber,
  encodeUnconstrainedWholeNumber,
  decodeUnconstrainedWholeNumber,
} from '../src/helpers';

describe('helpers', () => {
  describe('constrainedWholeNumberBitCount', () => {
    it('returns 0 for range of 1', () => {
      expect(constrainedWholeNumberBitCount(5, 5)).toBe(0);
    });

    it('returns 1 for range of 2', () => {
      expect(constrainedWholeNumberBitCount(0, 1)).toBe(1);
    });

    it('returns correct bits for powers of 2', () => {
      expect(constrainedWholeNumberBitCount(0, 3)).toBe(2);
      expect(constrainedWholeNumberBitCount(0, 7)).toBe(3);
      expect(constrainedWholeNumberBitCount(0, 15)).toBe(4);
      expect(constrainedWholeNumberBitCount(0, 255)).toBe(8);
    });

    it('returns correct bits for non-powers of 2', () => {
      expect(constrainedWholeNumberBitCount(0, 2)).toBe(2); // range=3, needs 2 bits
      expect(constrainedWholeNumberBitCount(0, 5)).toBe(3); // range=6, needs 3 bits
      expect(constrainedWholeNumberBitCount(0, 99)).toBe(7); // range=100, needs 7 bits
    });

    it('throws for invalid range', () => {
      expect(() => constrainedWholeNumberBitCount(5, 4)).toThrow();
    });
  });

  describe('encodeConstrainedWholeNumber / decodeConstrainedWholeNumber', () => {
    it('encodes and decodes within range', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedWholeNumber(buf, 3, 0, 7);
      buf.reset();
      expect(decodeConstrainedWholeNumber(buf, 0, 7)).toBe(3);
    });

    it('encodes minimum value', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedWholeNumber(buf, 10, 10, 20);
      buf.reset();
      expect(decodeConstrainedWholeNumber(buf, 10, 20)).toBe(10);
    });

    it('encodes maximum value', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedWholeNumber(buf, 20, 10, 20);
      buf.reset();
      expect(decodeConstrainedWholeNumber(buf, 10, 20)).toBe(20);
    });

    it('writes zero bits when range is 1', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedWholeNumber(buf, 5, 5, 5);
      expect(buf.bitLength).toBe(0);
      buf.reset();
      expect(decodeConstrainedWholeNumber(buf, 5, 5)).toBe(5);
    });

    it('throws when value out of range', () => {
      const buf = BitBuffer.alloc();
      expect(() => encodeConstrainedWholeNumber(buf, 8, 0, 7)).toThrow();
      expect(() => encodeConstrainedWholeNumber(buf, -1, 0, 7)).toThrow();
    });
  });

  describe('encodeUnconstrainedLength / decodeUnconstrainedLength', () => {
    it('encodes short form (0..127)', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedLength(buf, 0);
      expect(buf.bitLength).toBe(8); // 1 + 7 bits
      buf.reset();
      expect(decodeUnconstrainedLength(buf)).toBe(0);
    });

    it('encodes value 127', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedLength(buf, 127);
      buf.reset();
      expect(decodeUnconstrainedLength(buf)).toBe(127);
    });

    it('encodes long form (128..16383)', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedLength(buf, 128);
      expect(buf.bitLength).toBe(16); // 2 + 14 bits
      buf.reset();
      expect(decodeUnconstrainedLength(buf)).toBe(128);
    });

    it('encodes value 16383', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedLength(buf, 16383);
      buf.reset();
      expect(decodeUnconstrainedLength(buf)).toBe(16383);
    });

    it('throws for negative length', () => {
      const buf = BitBuffer.alloc();
      expect(() => encodeUnconstrainedLength(buf, -1)).toThrow();
    });
  });

  describe('encodeConstrainedLength / decodeConstrainedLength', () => {
    it('writes zero bits for range of 1', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedLength(buf, 5, 5, 5);
      expect(buf.bitLength).toBe(0);
      buf.reset();
      expect(decodeConstrainedLength(buf, 5, 5)).toBe(5);
    });

    it('encodes as constrained whole number for small range', () => {
      const buf = BitBuffer.alloc();
      encodeConstrainedLength(buf, 3, 0, 7);
      buf.reset();
      expect(decodeConstrainedLength(buf, 0, 7)).toBe(3);
    });
  });

  describe('encodeNormallySmallNumber / decodeNormallySmallNumber', () => {
    it('encodes values < 64', () => {
      const buf = BitBuffer.alloc();
      encodeNormallySmallNumber(buf, 0);
      expect(buf.bitLength).toBe(7); // 1 + 6 bits
      buf.reset();
      expect(decodeNormallySmallNumber(buf)).toBe(0);
    });

    it('encodes value 63', () => {
      const buf = BitBuffer.alloc();
      encodeNormallySmallNumber(buf, 63);
      buf.reset();
      expect(decodeNormallySmallNumber(buf)).toBe(63);
    });

    it('encodes values >= 64', () => {
      const buf = BitBuffer.alloc();
      encodeNormallySmallNumber(buf, 64);
      buf.reset();
      expect(decodeNormallySmallNumber(buf)).toBe(64);
    });

    it('encodes value 200', () => {
      const buf = BitBuffer.alloc();
      encodeNormallySmallNumber(buf, 200);
      buf.reset();
      expect(decodeNormallySmallNumber(buf)).toBe(200);
    });
  });

  describe('encodeSemiConstrainedWholeNumber / decodeSemiConstrainedWholeNumber', () => {
    it('encodes with minimum offset', () => {
      const buf = BitBuffer.alloc();
      encodeSemiConstrainedWholeNumber(buf, 10, 5);
      buf.reset();
      expect(decodeSemiConstrainedWholeNumber(buf, 5)).toBe(10);
    });

    it('encodes minimum value', () => {
      const buf = BitBuffer.alloc();
      encodeSemiConstrainedWholeNumber(buf, 0, 0);
      buf.reset();
      expect(decodeSemiConstrainedWholeNumber(buf, 0)).toBe(0);
    });

    it('throws for value below minimum', () => {
      const buf = BitBuffer.alloc();
      expect(() => encodeSemiConstrainedWholeNumber(buf, 4, 5)).toThrow();
    });
  });

  describe('encodeUnconstrainedWholeNumber / decodeUnconstrainedWholeNumber', () => {
    it('encodes zero', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedWholeNumber(buf, 0);
      buf.reset();
      expect(decodeUnconstrainedWholeNumber(buf)).toBe(0);
    });

    it('encodes positive value', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedWholeNumber(buf, 255);
      buf.reset();
      expect(decodeUnconstrainedWholeNumber(buf)).toBe(255);
    });

    it('encodes negative value', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedWholeNumber(buf, -1);
      buf.reset();
      expect(decodeUnconstrainedWholeNumber(buf)).toBe(-1);
    });

    it('encodes larger negative value', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedWholeNumber(buf, -128);
      buf.reset();
      expect(decodeUnconstrainedWholeNumber(buf)).toBe(-128);
    });

    it('encodes large positive value', () => {
      const buf = BitBuffer.alloc();
      encodeUnconstrainedWholeNumber(buf, 65535);
      buf.reset();
      expect(decodeUnconstrainedWholeNumber(buf)).toBe(65535);
    });
  });
});
