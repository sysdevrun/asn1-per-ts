import { BitBuffer } from '../../src/BitBuffer';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';

describe('IntegerCodec', () => {
  describe('constrained', () => {
    it('encodes/decodes value in range 0..7 (3 bits)', () => {
      const codec = new IntegerCodec({ min: 0, max: 7 });
      expect(codec.constraintType).toBe('constrained');
      expect(codec.bitWidth).toBe(3);

      const buf = BitBuffer.alloc();
      codec.encode(buf, 5);
      expect(buf.bitLength).toBe(3);
      buf.reset();
      expect(codec.decode(buf)).toBe(5);
    });

    it('encodes/decodes with offset range 10..20', () => {
      const codec = new IntegerCodec({ min: 10, max: 20 });

      for (const v of [10, 15, 20]) {
        const buf = BitBuffer.alloc();
        codec.encode(buf, v);
        buf.reset();
        expect(codec.decode(buf)).toBe(v);
      }
    });

    it('encodes single-value range with zero bits', () => {
      const codec = new IntegerCodec({ min: 42, max: 42 });
      expect(codec.bitWidth).toBe(0);

      const buf = BitBuffer.alloc();
      codec.encode(buf, 42);
      expect(buf.bitLength).toBe(0);
      buf.reset();
      expect(codec.decode(buf)).toBe(42);
    });

    it('throws when value out of range', () => {
      const codec = new IntegerCodec({ min: 0, max: 7 });
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 8)).toThrow();
      expect(() => codec.encode(buf, -1)).toThrow();
    });

    it('handles range 0..255 (8 bits)', () => {
      const codec = new IntegerCodec({ min: 0, max: 255 });
      expect(codec.bitWidth).toBe(8);

      const buf = BitBuffer.alloc();
      codec.encode(buf, 200);
      buf.reset();
      expect(codec.decode(buf)).toBe(200);
    });
  });

  describe('semi-constrained', () => {
    it('encodes/decodes with only min bound', () => {
      const codec = new IntegerCodec({ min: 0 });
      expect(codec.constraintType).toBe('semi-constrained');
      expect(codec.bitWidth).toBeUndefined();

      const buf = BitBuffer.alloc();
      codec.encode(buf, 100);
      buf.reset();
      expect(codec.decode(buf)).toBe(100);
    });

    it('encodes minimum value', () => {
      const codec = new IntegerCodec({ min: 5 });
      const buf = BitBuffer.alloc();
      codec.encode(buf, 5);
      buf.reset();
      expect(codec.decode(buf)).toBe(5);
    });
  });

  describe('unconstrained', () => {
    it('encodes/decodes positive values', () => {
      const codec = new IntegerCodec();
      expect(codec.constraintType).toBe('unconstrained');

      const buf = BitBuffer.alloc();
      codec.encode(buf, 42);
      buf.reset();
      expect(codec.decode(buf)).toBe(42);
    });

    it('encodes/decodes negative values', () => {
      const codec = new IntegerCodec();
      const buf = BitBuffer.alloc();
      codec.encode(buf, -100);
      buf.reset();
      expect(codec.decode(buf)).toBe(-100);
    });

    it('encodes/decodes zero', () => {
      const codec = new IntegerCodec();
      const buf = BitBuffer.alloc();
      codec.encode(buf, 0);
      buf.reset();
      expect(codec.decode(buf)).toBe(0);
    });
  });

  describe('extensible', () => {
    it('encodes within range with extension bit 0', () => {
      const codec = new IntegerCodec({ min: 0, max: 7, extensible: true });
      const buf = BitBuffer.alloc();
      codec.encode(buf, 5);
      buf.reset();
      expect(buf.readBit()).toBe(0); // extension bit = 0
    });

    it('encodes out of range with extension bit 1', () => {
      const codec = new IntegerCodec({ min: 0, max: 7, extensible: true });
      const buf = BitBuffer.alloc();
      codec.encode(buf, 100);
      buf.reset();
      expect(buf.readBit()).toBe(1); // extension bit = 1
    });

    it('round-trips within range', () => {
      const codec = new IntegerCodec({ min: 0, max: 7, extensible: true });
      const buf = BitBuffer.alloc();
      codec.encode(buf, 3);
      buf.reset();
      expect(codec.decode(buf)).toBe(3);
    });

    it('round-trips out of range', () => {
      const codec = new IntegerCodec({ min: 0, max: 7, extensible: true });
      const buf = BitBuffer.alloc();
      codec.encode(buf, 256);
      buf.reset();
      expect(codec.decode(buf)).toBe(256);
    });

    it('round-trips negative out of range', () => {
      const codec = new IntegerCodec({ min: 0, max: 7, extensible: true });
      const buf = BitBuffer.alloc();
      codec.encode(buf, -5);
      buf.reset();
      expect(codec.decode(buf)).toBe(-5);
    });
  });
});
