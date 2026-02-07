import { BitBuffer } from './BitBuffer';

/**
 * Number of bits needed to encode a constrained whole number with range (max - min + 1).
 * Returns 0 when range is 1 (single value, zero bits needed).
 */
export function constrainedWholeNumberBitCount(min: number, max: number): number {
  const range = max - min + 1;
  if (range <= 0) throw new Error(`Invalid constraint: min=${min} > max=${max}`);
  if (range === 1) return 0;
  return Math.ceil(Math.log2(range));
}

/**
 * Encode a constrained whole number (X.691 §10.5).
 * Encodes (value - min) in ceil(log2(range)) bits.
 */
export function encodeConstrainedWholeNumber(
  buf: BitBuffer, value: number, min: number, max: number
): void {
  if (value < min || value > max) {
    throw new Error(`Value ${value} out of constrained range [${min}, ${max}]`);
  }
  const bitCount = constrainedWholeNumberBitCount(min, max);
  if (bitCount === 0) return;
  buf.writeBits(value - min, bitCount);
}

/**
 * Decode a constrained whole number (X.691 §10.5).
 */
export function decodeConstrainedWholeNumber(
  buf: BitBuffer, min: number, max: number
): number {
  const bitCount = constrainedWholeNumberBitCount(min, max);
  if (bitCount === 0) return min;
  return buf.readBits(bitCount) + min;
}

/**
 * Encode an unconstrained length determinant (X.691 §10.9).
 *   0..127:       0 + 7-bit value
 *   128..16383:   10 + 14-bit value
 *   >=16384:      fragmented (11 + 6-bit fragment count, each fragment is 16K items)
 */
export function encodeUnconstrainedLength(buf: BitBuffer, length: number): void {
  if (length < 0) throw new Error(`Length must be non-negative, got ${length}`);
  if (length < 128) {
    buf.writeBit(0);
    buf.writeBits(length, 7);
  } else if (length < 16384) {
    buf.writeBit(1);
    buf.writeBit(0);
    buf.writeBits(length, 14);
  } else {
    // Fragmented encoding is complex; for practical use we support up to 16383
    // For larger values, encode as fragmented
    throw new Error(`Length ${length} >= 16384 requires fragmented encoding (not yet supported)`);
  }
}

/**
 * Decode an unconstrained length determinant (X.691 §10.9).
 */
export function decodeUnconstrainedLength(buf: BitBuffer): number {
  const firstBit = buf.readBit();
  if (firstBit === 0) {
    return buf.readBits(7);
  }
  const secondBit = buf.readBit();
  if (secondBit === 0) {
    return buf.readBits(14);
  }
  throw new Error('Fragmented length determinant decoding not yet supported');
}

/**
 * Encode a constrained length determinant.
 * If range == 1, writes zero bits.
 * If range <= 65536, encodes as constrained whole number.
 * Otherwise, uses unconstrained length.
 */
export function encodeConstrainedLength(
  buf: BitBuffer, length: number, min: number, max: number
): void {
  if (length < min || length > max) {
    throw new Error(`Length ${length} out of range [${min}, ${max}]`);
  }
  const range = max - min + 1;
  if (range === 1) return;
  if (range <= 65536) {
    encodeConstrainedWholeNumber(buf, length, min, max);
  } else {
    encodeUnconstrainedLength(buf, length);
  }
}

/**
 * Decode a constrained length determinant.
 */
export function decodeConstrainedLength(
  buf: BitBuffer, min: number, max: number
): number {
  const range = max - min + 1;
  if (range === 1) return min;
  if (range <= 65536) {
    return decodeConstrainedWholeNumber(buf, min, max);
  }
  return decodeUnconstrainedLength(buf);
}

/**
 * Encode a normally small non-negative whole number (X.691 §10.6).
 *   value < 64:  0 + 6-bit value
 *   value >= 64: 1 + semi-constrained encoding
 */
export function encodeNormallySmallNumber(buf: BitBuffer, value: number): void {
  if (value < 0) throw new Error(`Normally small number must be non-negative, got ${value}`);
  if (value < 64) {
    buf.writeBit(0);
    buf.writeBits(value, 6);
  } else {
    buf.writeBit(1);
    encodeSemiConstrainedWholeNumber(buf, value, 0);
  }
}

/**
 * Decode a normally small non-negative whole number (X.691 §10.6).
 */
export function decodeNormallySmallNumber(buf: BitBuffer): number {
  const flag = buf.readBit();
  if (flag === 0) {
    return buf.readBits(6);
  }
  return decodeSemiConstrainedWholeNumber(buf, 0);
}

/**
 * Encode a semi-constrained whole number (X.691 §10.7).
 * Lower bound known, no upper bound.
 * Encodes (value - min) as: unconstrained length (in octets) + unsigned integer bytes.
 */
export function encodeSemiConstrainedWholeNumber(
  buf: BitBuffer, value: number, min: number
): void {
  if (value < min) {
    throw new Error(`Value ${value} below minimum ${min}`);
  }
  const offset = value - min;
  const bytes = unsignedIntToBytes(offset);
  encodeUnconstrainedLength(buf, bytes.length);
  buf.writeOctets(bytes);
}

/**
 * Decode a semi-constrained whole number (X.691 §10.7).
 */
export function decodeSemiConstrainedWholeNumber(
  buf: BitBuffer, min: number
): number {
  const len = decodeUnconstrainedLength(buf);
  const bytes = buf.readOctets(len);
  return bytesToUnsignedInt(bytes) + min;
}

/**
 * Encode an unconstrained whole number (X.691 §10.8).
 * No bounds known. Two's complement encoding.
 */
export function encodeUnconstrainedWholeNumber(
  buf: BitBuffer, value: number
): void {
  const bytes = signedIntToBytes(value);
  encodeUnconstrainedLength(buf, bytes.length);
  buf.writeOctets(bytes);
}

/**
 * Decode an unconstrained whole number (X.691 §10.8).
 */
export function decodeUnconstrainedWholeNumber(buf: BitBuffer): number {
  const len = decodeUnconstrainedLength(buf);
  const bytes = buf.readOctets(len);
  return bytesToSignedInt(bytes);
}

/** Convert unsigned integer to minimum-width big-endian byte array. */
function unsignedIntToBytes(value: number): Uint8Array {
  if (value === 0) return new Uint8Array([0]);
  const bytes: number[] = [];
  let v = value;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return new Uint8Array(bytes);
}

/** Convert big-endian bytes to unsigned integer. */
function bytesToUnsignedInt(bytes: Uint8Array): number {
  let result = 0;
  for (let i = 0; i < bytes.length; i++) {
    result = result * 256 + bytes[i];
  }
  return result;
}

/** Convert signed integer to minimum-width big-endian two's complement byte array. */
function signedIntToBytes(value: number): Uint8Array {
  if (value === 0) return new Uint8Array([0]);
  if (value > 0) {
    const bytes = unsignedIntToBytes(value);
    // If high bit is set, prepend a zero byte
    if (bytes[0] & 0x80) {
      const result = new Uint8Array(bytes.length + 1);
      result.set(bytes, 1);
      return result;
    }
    return bytes;
  }
  // Negative value: extract bytes via arithmetic right shift
  const bytes: number[] = [];
  let v = value;
  while (v < -1) {
    bytes.unshift(v & 0xff);
    v = v >> 8;
  }
  bytes.unshift(v & 0xff); // leading 0xff for sign
  // Trim redundant leading 0xff bytes (sign extension)
  while (bytes.length > 1 && bytes[0] === 0xff && (bytes[1] & 0x80)) {
    bytes.shift();
  }
  return new Uint8Array(bytes);
}

/** Convert big-endian two's complement bytes to signed integer. */
function bytesToSignedInt(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const isNegative = (bytes[0] & 0x80) !== 0;
  if (!isNegative) return bytesToUnsignedInt(bytes);
  // Invert bits and add 1 to get absolute value
  const inverted = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    inverted[i] = ~bytes[i] & 0xff;
  }
  let carry = 1;
  for (let i = inverted.length - 1; i >= 0 && carry; i--) {
    const sum = inverted[i] + carry;
    inverted[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return -bytesToUnsignedInt(inverted);
}
