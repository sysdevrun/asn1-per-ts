import { BitBuffer } from '../../src/BitBuffer';
import { OctetStringCodec } from '../../src/codecs/OctetStringCodec';

describe('OctetStringCodec', () => {
  describe('fixed size', () => {
    const codec = new OctetStringCodec({ fixedSize: 4 });

    it('encodes exactly fixedSize octets', () => {
      const value = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      expect(buf.bitLength).toBe(32);

      buf.reset();
      expect(codec.decode(buf)).toEqual(value);
    });

    it('throws when size does not match', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, new Uint8Array([1, 2, 3]))).toThrow();
    });
  });

  describe('constrained size', () => {
    const codec = new OctetStringCodec({ minSize: 1, maxSize: 4 });

    it('round-trips various sizes', () => {
      for (const len of [1, 2, 3, 4]) {
        const value = new Uint8Array(len);
        value.fill(0xAB);
        const buf = BitBuffer.alloc();
        codec.encode(buf, value);
        buf.reset();
        expect(codec.decode(buf)).toEqual(value);
      }
    });

    it('throws for out-of-range size', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, new Uint8Array(0))).toThrow();
      expect(() => codec.encode(buf, new Uint8Array(5))).toThrow();
    });
  });

  describe('unconstrained', () => {
    const codec = new OctetStringCodec();

    it('round-trips empty octet string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, new Uint8Array(0));
      buf.reset();
      expect(codec.decode(buf)).toEqual(new Uint8Array(0));
    });

    it('round-trips non-empty octet string', () => {
      const value = new Uint8Array([1, 2, 3, 4, 5]);
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(codec.decode(buf)).toEqual(value);
    });
  });

  describe('extensible', () => {
    const codec = new OctetStringCodec({ fixedSize: 2, extensible: true });

    it('encodes within constraint', () => {
      const value = new Uint8Array([0xAB, 0xCD]);
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(codec.decode(buf)).toEqual(value);
    });

    it('encodes outside constraint with extension', () => {
      const value = new Uint8Array([0xAB, 0xCD, 0xEF]);
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(codec.decode(buf)).toEqual(value);
    });
  });
});
