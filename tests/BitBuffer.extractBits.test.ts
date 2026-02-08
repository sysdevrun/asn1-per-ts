import { BitBuffer } from '../src/BitBuffer';

describe('BitBuffer.extractBits', () => {
  test('extracts zero bits', () => {
    const buf = BitBuffer.from(new Uint8Array([0xff]));
    const result = buf.extractBits(0, 0);
    expect(result).toEqual(new Uint8Array(0));
  });

  test('extracts full byte from start', () => {
    const buf = BitBuffer.from(new Uint8Array([0xab, 0xcd]));
    const result = buf.extractBits(0, 8);
    expect(result).toEqual(new Uint8Array([0xab]));
  });

  test('extracts second byte', () => {
    const buf = BitBuffer.from(new Uint8Array([0xab, 0xcd]));
    const result = buf.extractBits(8, 8);
    expect(result).toEqual(new Uint8Array([0xcd]));
  });

  test('extracts bits across byte boundary', () => {
    // 0xab = 10101011, 0xcd = 11001101
    // bits 4..11 = 1011_1100 = 0xbc
    const buf = BitBuffer.from(new Uint8Array([0xab, 0xcd]));
    const result = buf.extractBits(4, 8);
    expect(result).toEqual(new Uint8Array([0xbc]));
  });

  test('extracts partial byte with zero-padding', () => {
    // 0xff = 11111111
    // bits 0..3 = 1111 → left-aligned → 11110000 = 0xf0
    const buf = BitBuffer.from(new Uint8Array([0xff]));
    const result = buf.extractBits(0, 4);
    expect(result).toEqual(new Uint8Array([0xf0]));
  });

  test('extracts single bit (1)', () => {
    const buf = BitBuffer.from(new Uint8Array([0x80]));
    const result = buf.extractBits(0, 1);
    expect(result).toEqual(new Uint8Array([0x80]));
  });

  test('extracts single bit (0)', () => {
    const buf = BitBuffer.from(new Uint8Array([0x00]));
    const result = buf.extractBits(0, 1);
    expect(result).toEqual(new Uint8Array([0x00]));
  });

  test('does not alter buffer offset', () => {
    const buf = BitBuffer.from(new Uint8Array([0xab, 0xcd]));
    buf.readBit(); // advance cursor to 1
    const offsetBefore = buf.offset;
    buf.extractBits(0, 8);
    expect(buf.offset).toBe(offsetBefore);
  });

  test('extracts multi-byte range', () => {
    const buf = BitBuffer.from(new Uint8Array([0x12, 0x34, 0x56]));
    const result = buf.extractBits(0, 24);
    expect(result).toEqual(new Uint8Array([0x12, 0x34, 0x56]));
  });

  test('extracts 3 bits starting mid-byte', () => {
    // 0xa5 = 10100101
    // bits 2..4 = 100 → left-aligned → 10000000 = 0x80
    const buf = BitBuffer.from(new Uint8Array([0xa5]));
    const result = buf.extractBits(2, 3);
    expect(result).toEqual(new Uint8Array([0x80]));
  });
});
