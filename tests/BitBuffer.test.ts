import { BitBuffer } from '../src/BitBuffer';

describe('BitBuffer', () => {
  describe('alloc and basic properties', () => {
    it('starts with zero bitLength and offset', () => {
      const buf = BitBuffer.alloc();
      expect(buf.bitLength).toBe(0);
      expect(buf.offset).toBe(0);
      expect(buf.remaining).toBe(0);
    });
  });

  describe('writeBit / readBit', () => {
    it('writes and reads single bits', () => {
      const buf = BitBuffer.alloc();
      buf.writeBit(1);
      buf.writeBit(0);
      buf.writeBit(1);
      buf.writeBit(1);
      expect(buf.bitLength).toBe(4);

      buf.reset();
      expect(buf.readBit()).toBe(1);
      expect(buf.readBit()).toBe(0);
      expect(buf.readBit()).toBe(1);
      expect(buf.readBit()).toBe(1);
    });

    it('throws when reading past end', () => {
      const buf = BitBuffer.alloc();
      buf.writeBit(1);
      buf.reset();
      buf.readBit();
      expect(() => buf.readBit()).toThrow('read past end');
    });
  });

  describe('writeBits / readBits', () => {
    it('writes and reads multi-bit values', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0b10110, 5);
      buf.writeBits(0b11, 2);
      expect(buf.bitLength).toBe(7);

      buf.reset();
      expect(buf.readBits(5)).toBe(0b10110);
      expect(buf.readBits(2)).toBe(0b11);
    });

    it('handles 0 bits', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0, 0);
      expect(buf.bitLength).toBe(0);
      expect(buf.readBits(0)).toBe(0);
    });

    it('handles 32-bit values', () => {
      const buf = BitBuffer.alloc();
      const value = 0xDEADBEEF;
      buf.writeBits(value, 32);
      buf.reset();
      expect(buf.readBits(32)).toBe(value);
    });

    it('throws for count > 32', () => {
      const buf = BitBuffer.alloc();
      expect(() => buf.writeBits(0, 33)).toThrow();
      expect(() => buf.readBits(33)).toThrow();
    });
  });

  describe('writeBigBits / readBigBits', () => {
    it('handles arbitrary-width bigint values', () => {
      const buf = BitBuffer.alloc();
      const value = 0xDEADBEEFCAFEn;
      buf.writeBigBits(value, 48);
      buf.reset();
      expect(buf.readBigBits(48)).toBe(value);
    });

    it('handles 0 bits', () => {
      const buf = BitBuffer.alloc();
      buf.writeBigBits(0n, 0);
      expect(buf.readBigBits(0)).toBe(0n);
    });
  });

  describe('writeOctets / readOctets', () => {
    it('writes and reads byte arrays', () => {
      const buf = BitBuffer.alloc();
      const data = new Uint8Array([0xAB, 0xCD, 0xEF]);
      buf.writeOctets(data);
      expect(buf.bitLength).toBe(24);

      buf.reset();
      const result = buf.readOctets(3);
      expect(result).toEqual(data);
    });

    it('works with non-byte-aligned offset', () => {
      const buf = BitBuffer.alloc();
      buf.writeBit(1);
      buf.writeOctets(new Uint8Array([0xFF]));
      expect(buf.bitLength).toBe(9);

      buf.reset();
      expect(buf.readBit()).toBe(1);
      expect(buf.readOctets(1)).toEqual(new Uint8Array([0xFF]));
    });
  });

  describe('from', () => {
    it('wraps existing bytes', () => {
      const buf = BitBuffer.from(new Uint8Array([0b10110000]), 5);
      expect(buf.bitLength).toBe(5);
      expect(buf.readBits(5)).toBe(0b10110);
    });

    it('defaults bitLength to data.length * 8', () => {
      const buf = BitBuffer.from(new Uint8Array([0xAB, 0xCD]));
      expect(buf.bitLength).toBe(16);
    });
  });

  describe('fromBinaryString', () => {
    it('parses binary string', () => {
      const buf = BitBuffer.fromBinaryString('10110');
      expect(buf.bitLength).toBe(5);
      expect(buf.readBits(5)).toBe(0b10110);
    });

    it('throws for invalid characters', () => {
      expect(() => BitBuffer.fromBinaryString('102')).toThrow('Invalid binary character');
    });
  });

  describe('toUint8Array', () => {
    it('returns compact byte array', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0b10110, 5);
      const arr = buf.toUint8Array();
      expect(arr.length).toBe(1);
      expect(arr[0]).toBe(0b10110000);
    });
  });

  describe('toBinaryString', () => {
    it('returns string of 0s and 1s', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0b10110, 5);
      expect(buf.toBinaryString()).toBe('10110');
    });

    it('preserves cursor position', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0b1011, 4);
      buf.seek(2);
      buf.toBinaryString();
      expect(buf.offset).toBe(2);
    });
  });

  describe('toHex', () => {
    it('returns hex string', () => {
      const buf = BitBuffer.alloc();
      buf.writeOctets(new Uint8Array([0xAB, 0xCD]));
      expect(buf.toHex()).toBe('abcd');
    });
  });

  describe('seek', () => {
    it('moves cursor to absolute position', () => {
      const buf = BitBuffer.alloc();
      buf.writeBits(0b1010, 4);
      buf.seek(2);
      expect(buf.offset).toBe(2);
      expect(buf.readBit()).toBe(1);
    });

    it('throws for out-of-range offset', () => {
      const buf = BitBuffer.alloc();
      buf.writeBit(1);
      expect(() => buf.seek(-1)).toThrow();
      expect(() => buf.seek(2)).toThrow();
    });
  });

  describe('auto-grow', () => {
    it('grows buffer when writing past initial capacity', () => {
      const buf = BitBuffer.alloc(1); // 1 byte initial
      for (let i = 0; i < 100; i++) {
        buf.writeBit(i % 2 === 0 ? 1 : 0);
      }
      expect(buf.bitLength).toBe(100);
      buf.reset();
      for (let i = 0; i < 100; i++) {
        expect(buf.readBit()).toBe(i % 2 === 0 ? 1 : 0);
      }
    });
  });

  describe('round-trip encoding', () => {
    it('handles mixed operations', () => {
      const buf = BitBuffer.alloc();
      buf.writeBit(1);
      buf.writeBits(42, 8);
      buf.writeOctets(new Uint8Array([0xDE, 0xAD]));
      buf.writeBits(7, 3);

      buf.reset();
      expect(buf.readBit()).toBe(1);
      expect(buf.readBits(8)).toBe(42);
      expect(buf.readOctets(2)).toEqual(new Uint8Array([0xDE, 0xAD]));
      expect(buf.readBits(3)).toBe(7);
      expect(buf.remaining).toBe(0);
    });
  });
});
