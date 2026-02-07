import { BitBuffer } from '../../src/BitBuffer';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';

describe('BooleanCodec', () => {
  const codec = new BooleanCodec();

  it('encodes true as bit 1', () => {
    const buf = BitBuffer.alloc();
    codec.encode(buf, true);
    expect(buf.bitLength).toBe(1);
    expect(buf.toBinaryString()).toBe('1');
  });

  it('encodes false as bit 0', () => {
    const buf = BitBuffer.alloc();
    codec.encode(buf, false);
    expect(buf.bitLength).toBe(1);
    expect(buf.toBinaryString()).toBe('0');
  });

  it('decodes bit 1 as true', () => {
    const buf = BitBuffer.fromBinaryString('1');
    expect(codec.decode(buf)).toBe(true);
  });

  it('decodes bit 0 as false', () => {
    const buf = BitBuffer.fromBinaryString('0');
    expect(codec.decode(buf)).toBe(false);
  });

  it('round-trips correctly', () => {
    for (const value of [true, false]) {
      const buf = BitBuffer.alloc();
      codec.encode(buf, value);
      buf.reset();
      expect(codec.decode(buf)).toBe(value);
    }
  });

  it('encodes multiple booleans sequentially', () => {
    const buf = BitBuffer.alloc();
    codec.encode(buf, true);
    codec.encode(buf, false);
    codec.encode(buf, true);
    expect(buf.bitLength).toBe(3);
    expect(buf.toBinaryString()).toBe('101');

    buf.reset();
    expect(codec.decode(buf)).toBe(true);
    expect(codec.decode(buf)).toBe(false);
    expect(codec.decode(buf)).toBe(true);
  });
});
