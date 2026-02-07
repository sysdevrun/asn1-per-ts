import { BitBuffer } from '../../src/BitBuffer';
import { EnumeratedCodec } from '../../src/codecs/EnumeratedCodec';

describe('EnumeratedCodec', () => {
  describe('non-extensible', () => {
    const codec = new EnumeratedCodec({
      values: ['red', 'green', 'blue', 'yellow'],
    });

    it('is not extensible', () => {
      expect(codec.extensible).toBe(false);
    });

    it('encodes first value', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'red');
      buf.reset();
      expect(codec.decode(buf)).toBe('red');
    });

    it('encodes last value', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'yellow');
      buf.reset();
      expect(codec.decode(buf)).toBe('yellow');
    });

    it('round-trips all values', () => {
      for (const val of ['red', 'green', 'blue', 'yellow']) {
        const buf = BitBuffer.alloc();
        codec.encode(buf, val);
        buf.reset();
        expect(codec.decode(buf)).toBe(val);
      }
    });

    it('throws for unknown value', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 'purple')).toThrow('Unknown enumerated value');
    });

    it('uses correct number of bits', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'red');
      // range = 4, needs 2 bits
      expect(buf.bitLength).toBe(2);
    });
  });

  describe('extensible', () => {
    const codec = new EnumeratedCodec({
      values: ['red', 'green', 'blue'],
      extensionValues: ['purple', 'orange'],
    });

    it('is extensible', () => {
      expect(codec.extensible).toBe(true);
    });

    it('encodes root value with ext bit 0', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'red');
      buf.reset();
      expect(buf.readBit()).toBe(0);
    });

    it('encodes extension value with ext bit 1', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'purple');
      buf.reset();
      expect(buf.readBit()).toBe(1);
    });

    it('round-trips root values', () => {
      for (const val of ['red', 'green', 'blue']) {
        const buf = BitBuffer.alloc();
        codec.encode(buf, val);
        buf.reset();
        expect(codec.decode(buf)).toBe(val);
      }
    });

    it('round-trips extension values', () => {
      for (const val of ['purple', 'orange']) {
        const buf = BitBuffer.alloc();
        codec.encode(buf, val);
        buf.reset();
        expect(codec.decode(buf)).toBe(val);
      }
    });

    it('throws for completely unknown value', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 'cyan')).toThrow();
    });
  });

  describe('single value', () => {
    const codec = new EnumeratedCodec({ values: ['only'] });

    it('encodes single value in 0 bits', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'only');
      expect(buf.bitLength).toBe(0);
      buf.reset();
      expect(codec.decode(buf)).toBe('only');
    });
  });

  it('throws when constructed with empty values', () => {
    expect(() => new EnumeratedCodec({ values: [] })).toThrow();
  });
});
