import { BitBuffer } from '../../src/BitBuffer';
import { NullCodec } from '../../src/codecs/NullCodec';

describe('NullCodec', () => {
  const codec = new NullCodec();

  it('encodes without writing any bits', () => {
    const buf = BitBuffer.alloc();
    codec.encode(buf, null);
    expect(buf.bitLength).toBe(0);
  });

  it('decodes without consuming any bits', () => {
    const buf = BitBuffer.alloc();
    buf.writeBit(1);
    buf.reset();
    const result = codec.decode(buf);
    expect(result).toBeNull();
    expect(buf.offset).toBe(0);
  });

  it('round-trips correctly', () => {
    const buf = BitBuffer.alloc();
    codec.encode(buf, null);
    buf.reset();
    expect(codec.decode(buf)).toBeNull();
  });
});
