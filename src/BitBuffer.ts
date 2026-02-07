/**
 * Bit-level buffer for PER unaligned encoding/decoding.
 * Manages a growable byte array with a bit-level cursor.
 * Bits are stored MSB-first within each byte (big-endian bit order).
 */
export class BitBuffer {
  private _data: Uint8Array;
  private _bitLength: number;
  private _offset: number;

  private constructor(data: Uint8Array, bitLength: number, offset: number) {
    this._data = data;
    this._bitLength = bitLength;
    this._offset = offset;
  }

  /** Allocate a writable buffer with optional initial byte capacity. */
  static alloc(initialByteCapacity = 256): BitBuffer {
    return new BitBuffer(new Uint8Array(initialByteCapacity), 0, 0);
  }

  /** Wrap existing bytes as a buffer for reading. */
  static from(data: Uint8Array, bitLength?: number): BitBuffer {
    const bl = bitLength ?? data.length * 8;
    const copy = new Uint8Array(data);
    return new BitBuffer(copy, bl, 0);
  }

  /** Parse a binary string ('0' and '1' characters) into a buffer. */
  static fromBinaryString(bits: string): BitBuffer {
    const buf = BitBuffer.alloc(Math.ceil(bits.length / 8) || 1);
    for (const ch of bits) {
      if (ch !== '0' && ch !== '1') {
        throw new Error(`Invalid binary character: '${ch}'`);
      }
      buf.writeBit(ch === '1' ? 1 : 0);
    }
    buf.reset();
    return buf;
  }

  /** Total number of valid bits. */
  get bitLength(): number {
    return this._bitLength;
  }

  /** Current cursor position in bits. */
  get offset(): number {
    return this._offset;
  }

  /** Bits remaining from cursor to end. */
  get remaining(): number {
    return this._bitLength - this._offset;
  }

  /** Write a single bit. */
  writeBit(bit: 0 | 1): void {
    this.ensureCapacity(this._offset + 1);
    const byteIndex = this._offset >> 3;
    const bitIndex = 7 - (this._offset & 7);
    if (bit) {
      this._data[byteIndex] |= (1 << bitIndex);
    } else {
      this._data[byteIndex] &= ~(1 << bitIndex);
    }
    this._offset++;
    if (this._offset > this._bitLength) {
      this._bitLength = this._offset;
    }
  }

  /** Read a single bit. */
  readBit(): 0 | 1 {
    if (this._offset >= this._bitLength) {
      throw new Error('BitBuffer: read past end of buffer');
    }
    const byteIndex = this._offset >> 3;
    const bitIndex = 7 - (this._offset & 7);
    this._offset++;
    return ((this._data[byteIndex] >> bitIndex) & 1) as 0 | 1;
  }

  /**
   * Write the lowest `count` bits of `value` (MSB first).
   * @param value  unsigned integer (0..2^32-1)
   * @param count  number of bits to write (0..32)
   */
  writeBits(value: number, count: number): void {
    if (count === 0) return;
    if (count < 0 || count > 32) {
      throw new Error(`writeBits: count must be 0..32, got ${count}`);
    }
    for (let i = count - 1; i >= 0; i--) {
      this.writeBit(((value >> i) & 1) as 0 | 1);
    }
  }

  /**
   * Read `count` bits and return as unsigned integer.
   * @param count  number of bits to read (0..32)
   */
  readBits(count: number): number {
    if (count === 0) return 0;
    if (count < 0 || count > 32) {
      throw new Error(`readBits: count must be 0..32, got ${count}`);
    }
    let result = 0;
    for (let i = 0; i < count; i++) {
      result = (result << 1) | this.readBit();
    }
    return result >>> 0; // ensure unsigned
  }

  /** Write arbitrary-width bits from a bigint value (MSB first). */
  writeBigBits(value: bigint, count: number): void {
    if (count === 0) return;
    for (let i = count - 1; i >= 0; i--) {
      this.writeBit(Number((value >> BigInt(i)) & 1n) as 0 | 1);
    }
  }

  /** Read arbitrary-width bits into a bigint. */
  readBigBits(count: number): bigint {
    if (count === 0) return 0n;
    let result = 0n;
    for (let i = 0; i < count; i++) {
      result = (result << 1n) | BigInt(this.readBit());
    }
    return result;
  }

  /** Write raw bytes (each byte = 8 bits). */
  writeOctets(data: Uint8Array): void {
    for (let i = 0; i < data.length; i++) {
      this.writeBits(data[i], 8);
    }
  }

  /** Read raw bytes. */
  readOctets(byteCount: number): Uint8Array {
    const result = new Uint8Array(byteCount);
    for (let i = 0; i < byteCount; i++) {
      result[i] = this.readBits(8);
    }
    return result;
  }

  /** Return compact Uint8Array with trailing bits zero-padded. */
  toUint8Array(): Uint8Array {
    const byteLen = Math.ceil(this._bitLength / 8);
    return this._data.slice(0, byteLen);
  }

  /** Return binary string representation. */
  toBinaryString(): string {
    let result = '';
    const savedOffset = this._offset;
    this._offset = 0;
    for (let i = 0; i < this._bitLength; i++) {
      result += this.readBit().toString();
    }
    this._offset = savedOffset;
    return result;
  }

  /** Return hex string representation. */
  toHex(): string {
    const bytes = this.toUint8Array();
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** Reset cursor to 0. */
  reset(): void {
    this._offset = 0;
  }

  /** Seek to absolute bit offset. */
  seek(bitOffset: number): void {
    if (bitOffset < 0 || bitOffset > this._bitLength) {
      throw new Error(`seek: offset ${bitOffset} out of range [0, ${this._bitLength}]`);
    }
    this._offset = bitOffset;
  }

  private ensureCapacity(bitsNeeded: number): void {
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    if (bytesNeeded <= this._data.length) return;
    let newSize = this._data.length;
    while (newSize < bytesNeeded) {
      newSize *= 2;
    }
    const newData = new Uint8Array(newSize);
    newData.set(this._data);
    this._data = newData;
  }
}
