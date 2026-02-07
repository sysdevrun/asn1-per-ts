import { BitBuffer } from '../../src/BitBuffer';
import { BitStringCodec, BitStringValue } from '../../src/codecs/BitStringCodec';

describe('BitStringCodec', () => {
  describe('fixed size', () => {
    const codec = new BitStringCodec({ fixedSize: 8 });

    it('encodes exactly fixedSize bits', () => {
      const value: BitStringValue = { data: new Uint8Array([0b10110100]), bitLength: 8 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      expect(buf.bitLength).toBe(8);

      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(8);
      expect(result.data[0]).toBe(0b10110100);
    });

    it('throws when bitLength does not match fixedSize', () => {
      const value: BitStringValue = { data: new Uint8Array([0b10110000]), bitLength: 4 };
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, value)).toThrow();
    });
  });

  describe('constrained size', () => {
    const codec = new BitStringCodec({ minSize: 4, maxSize: 8 });

    it('round-trips minimum size', () => {
      const value: BitStringValue = { data: new Uint8Array([0b10100000]), bitLength: 4 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(4);
    });

    it('round-trips maximum size', () => {
      const value: BitStringValue = { data: new Uint8Array([0b11111111]), bitLength: 8 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(8);
      expect(result.data[0]).toBe(0xFF);
    });

    it('throws for out-of-range size', () => {
      const value: BitStringValue = { data: new Uint8Array([0xFF, 0xFF]), bitLength: 10 };
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, value)).toThrow();
    });
  });

  describe('unconstrained', () => {
    const codec = new BitStringCodec();

    it('round-trips arbitrary bit string', () => {
      const value: BitStringValue = { data: new Uint8Array([0b11010110, 0b10000000]), bitLength: 9 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(9);
    });
  });

  describe('extensible fixed size', () => {
    const codec = new BitStringCodec({ fixedSize: 4, extensible: true });

    it('encodes within constraint', () => {
      const value: BitStringValue = { data: new Uint8Array([0b10100000]), bitLength: 4 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(buf.readBit()).toBe(0); // ext bit = 0

      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(4);
    });

    it('encodes outside constraint with extension', () => {
      const value: BitStringValue = { data: new Uint8Array([0xFF]), bitLength: 8 };
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(buf.readBit()).toBe(1); // ext bit = 1

      buf.reset();
      const result = codec.decode(buf);
      expect(result.bitLength).toBe(8);
    });
  });
});
