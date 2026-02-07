import { BitBuffer } from '../../src/BitBuffer';
import { SequenceOfCodec } from '../../src/codecs/SequenceOfCodec';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';

describe('SequenceOfCodec', () => {
  describe('fixed size', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new IntegerCodec({ min: 0, max: 7 }),
      fixedSize: 3,
    });

    it('encodes exactly fixedSize items without length determinant', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, [1, 2, 3]);
      // 3 items * 3 bits each = 9 bits
      expect(buf.bitLength).toBe(9);
      buf.reset();
      expect(codec.decode(buf)).toEqual([1, 2, 3]);
    });

    it('throws when count does not match', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, [1, 2])).toThrow();
      expect(() => codec.encode(buf, [1, 2, 3, 4])).toThrow();
    });
  });

  describe('constrained size', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new BooleanCodec(),
      minSize: 1,
      maxSize: 5,
    });

    it('round-trips various sizes', () => {
      for (const items of [[true], [true, false], [true, false, true, false, true]]) {
        const buf = BitBuffer.alloc();
        codec.encode(buf, items);
        buf.reset();
        expect(codec.decode(buf)).toEqual(items);
      }
    });

    it('throws for out-of-range count', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, [])).toThrow();
      expect(() => codec.encode(buf, [true, true, true, true, true, true])).toThrow();
    });
  });

  describe('unconstrained', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new IntegerCodec({ min: 0, max: 255 }),
    });

    it('round-trips empty array', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, []);
      buf.reset();
      expect(codec.decode(buf)).toEqual([]);
    });

    it('round-trips non-empty array', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, [10, 20, 30]);
      buf.reset();
      expect(codec.decode(buf)).toEqual([10, 20, 30]);
    });
  });

  describe('extensible', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new BooleanCodec(),
      fixedSize: 2,
      extensible: true,
    });

    it('encodes within constraint', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, [true, false]);
      buf.reset();
      expect(buf.readBit()).toBe(0); // ext bit = 0
      buf.reset();
      expect(codec.decode(buf)).toEqual([true, false]);
    });

    it('encodes outside constraint', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, [true, false, true]);
      buf.reset();
      expect(buf.readBit()).toBe(1); // ext bit = 1
      buf.reset();
      expect(codec.decode(buf)).toEqual([true, false, true]);
    });
  });

  describe('nested sequence of', () => {
    const innerCodec = new SequenceOfCodec({
      itemCodec: new IntegerCodec({ min: 0, max: 3 }),
      minSize: 0,
      maxSize: 3,
    });
    const outerCodec = new SequenceOfCodec({
      itemCodec: innerCodec as any,
      minSize: 0,
      maxSize: 3,
    });

    it('round-trips nested arrays', () => {
      const value = [[1, 2], [3], []];
      const buf = BitBuffer.alloc();
      outerCodec.encode(buf, value);
      buf.reset();
      expect(outerCodec.decode(buf)).toEqual(value);
    });
  });
});
