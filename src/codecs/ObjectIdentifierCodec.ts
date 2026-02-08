import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import type { DecodedNode } from './DecodedNode';
import { primitiveDecodeWithMetadata } from './DecodedNode';
import {
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

/**
 * PER unaligned OBJECT IDENTIFIER codec (X.691 §23).
 *
 * Encodes/decodes OID values as dot-notation strings (e.g. "1.2.840.113549").
 * PER encoding: unconstrained length determinant + BER contents octets (X.690 §8.19).
 */
export class ObjectIdentifierCodec implements Codec<string> {
  encode(buffer: BitBuffer, value: string): void {
    const octets = oidStringToOctets(value);
    encodeUnconstrainedLength(buffer, octets.length);
    buffer.writeOctets(octets);
  }

  decode(buffer: BitBuffer): string {
    const len = decodeUnconstrainedLength(buffer);
    const octets = buffer.readOctets(len);
    return octetsToOidString(octets);
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    return primitiveDecodeWithMetadata(this, buffer);
  }
}

/**
 * Convert a dot-notation OID string to BER contents octets (X.690 §8.19).
 * First two arcs are encoded as (arc1 * 40 + arc2), remaining arcs as base-128 VLQ.
 */
function oidStringToOctets(oid: string): Uint8Array {
  const parts = oid.split('.').map(s => {
    const n = parseInt(s, 10);
    if (!Number.isFinite(n) || n < 0 || s !== String(n)) {
      throw new Error(`Invalid OID component: "${s}"`);
    }
    return n;
  });

  if (parts.length < 2) {
    throw new Error(`OID must have at least 2 components, got: "${oid}"`);
  }

  const first = parts[0];
  if (first > 2) {
    throw new Error(`OID first arc must be 0, 1, or 2, got: ${first}`);
  }
  if (first < 2 && parts[1] > 39) {
    throw new Error(`OID second arc must be 0..39 when first arc is ${first}, got: ${parts[1]}`);
  }

  const bytes: number[] = [];

  // First two arcs combined
  encodeBase128(bytes, first * 40 + parts[1]);

  // Remaining arcs
  for (let i = 2; i < parts.length; i++) {
    encodeBase128(bytes, parts[i]);
  }

  return new Uint8Array(bytes);
}

/**
 * Convert BER contents octets back to a dot-notation OID string.
 */
function octetsToOidString(octets: Uint8Array): string {
  if (octets.length === 0) {
    throw new Error('OID contents octets must not be empty');
  }

  const arcs: number[] = [];
  let offset = 0;

  // Decode first byte to get first two arcs
  const [firstCombined, newOffset] = decodeBase128(octets, offset);
  offset = newOffset;

  if (firstCombined < 40) {
    arcs.push(0, firstCombined);
  } else if (firstCombined < 80) {
    arcs.push(1, firstCombined - 40);
  } else {
    arcs.push(2, firstCombined - 80);
  }

  // Decode remaining arcs
  while (offset < octets.length) {
    const [value, next] = decodeBase128(octets, offset);
    offset = next;
    arcs.push(value);
  }

  return arcs.join('.');
}

/** Encode a non-negative integer as base-128 VLQ bytes, appending to the array. */
function encodeBase128(out: number[], value: number): void {
  if (value < 0) {
    throw new Error(`OID arc value must be non-negative, got: ${value}`);
  }

  // Collect 7-bit groups from least significant
  const groups: number[] = [];
  if (value === 0) {
    groups.push(0);
  } else {
    let v = value;
    while (v > 0) {
      groups.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    }
  }

  // Set high bit on all bytes except the last
  for (let i = 0; i < groups.length - 1; i++) {
    out.push(groups[i] | 0x80);
  }
  out.push(groups[groups.length - 1]);
}

/** Decode a base-128 VLQ value from octets at the given offset. Returns [value, nextOffset]. */
function decodeBase128(octets: Uint8Array, offset: number): [number, number] {
  let value = 0;
  let i = offset;

  while (i < octets.length) {
    const byte = octets[i];
    value = value * 128 + (byte & 0x7f);
    i++;
    if ((byte & 0x80) === 0) {
      return [value, i];
    }
  }

  throw new Error('Truncated base-128 encoding in OID');
}
