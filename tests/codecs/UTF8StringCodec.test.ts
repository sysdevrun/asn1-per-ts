import { BitBuffer } from '../../src/BitBuffer';
import { UTF8StringCodec } from '../../src/codecs/UTF8StringCodec';

describe('UTF8StringCodec', () => {
  describe('VisibleString with alphabet constraint', () => {
    const codec = new UTF8StringCodec({
      type: 'VisibleString',
      alphabet: 'ABCD',
      minSize: 1,
      maxSize: 10,
    });

    it('has correct bitsPerCharacter', () => {
      expect(codec.bitsPerCharacter).toBe(2); // 4 chars = 2 bits each
    });

    it('has sorted effective alphabet', () => {
      expect(codec.effectiveAlphabet).toEqual(['A', 'B', 'C', 'D']);
    });

    it('round-trips a string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'ABCD');
      buf.reset();
      expect(codec.decode(buf)).toBe('ABCD');
    });

    it('round-trips single char', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'C');
      buf.reset();
      expect(codec.decode(buf)).toBe('C');
    });

    it('throws for character outside alphabet', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 'ABCE')).toThrow('not in permitted alphabet');
    });

    it('throws for string too long', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 'ABCDABCDABC')).toThrow();
    });
  });

  describe('IA5String default alphabet', () => {
    const codec = new UTF8StringCodec({
      type: 'IA5String',
      minSize: 0,
      maxSize: 100,
    });

    it('has 7 bits per character', () => {
      expect(codec.bitsPerCharacter).toBe(7);
    });

    it('round-trips ASCII string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'Hello');
      buf.reset();
      expect(codec.decode(buf)).toBe('Hello');
    });
  });

  describe('VisibleString default alphabet', () => {
    const codec = new UTF8StringCodec({
      type: 'VisibleString',
      minSize: 0,
      maxSize: 50,
    });

    it('has 7 bits per character', () => {
      expect(codec.bitsPerCharacter).toBe(7);
    });

    it('round-trips printable string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'Test 123');
      buf.reset();
      expect(codec.decode(buf)).toBe('Test 123');
    });
  });

  describe('VisibleString fixed size', () => {
    const codec = new UTF8StringCodec({
      type: 'VisibleString',
      alphabet: 'AB',
      fixedSize: 3,
    });

    it('encodes fixed-length string without length determinant', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'ABA');
      // 2 chars = 1 bit each, 3 chars = 3 bits total
      expect(buf.bitLength).toBe(3);
      buf.reset();
      expect(codec.decode(buf)).toBe('ABA');
    });

    it('throws when length does not match', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, 'AB')).toThrow();
    });
  });

  describe('UTF8String', () => {
    const codec = new UTF8StringCodec({
      type: 'UTF8String',
    });

    it('round-trips ASCII string as octets', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'Hello');
      buf.reset();
      expect(codec.decode(buf)).toBe('Hello');
    });

    it('round-trips multi-byte UTF-8 string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'café');
      buf.reset();
      expect(codec.decode(buf)).toBe('café');
    });

    it('round-trips empty string', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, '');
      buf.reset();
      expect(codec.decode(buf)).toBe('');
    });
  });

  describe('extensible', () => {
    const codec = new UTF8StringCodec({
      type: 'VisibleString',
      alphabet: 'ABC',
      fixedSize: 2,
      extensible: true,
    });

    it('encodes within constraint', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'AB');
      buf.reset();
      expect(buf.readBit()).toBe(0);
      buf.reset();
      expect(codec.decode(buf)).toBe('AB');
    });

    it('encodes outside constraint with extension', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, 'ABCABC');
      buf.reset();
      expect(buf.readBit()).toBe(1);
      buf.reset();
      expect(codec.decode(buf)).toBe('ABCABC');
    });
  });

  describe('alphabet with duplicates', () => {
    const codec = new UTF8StringCodec({
      type: 'VisibleString',
      alphabet: 'AABBC',
      minSize: 0,
      maxSize: 5,
    });

    it('deduplicates alphabet', () => {
      expect(codec.effectiveAlphabet).toEqual(['A', 'B', 'C']);
    });
  });
});
