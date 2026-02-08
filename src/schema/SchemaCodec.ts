import { BitBuffer } from '../BitBuffer';
import { Codec } from '../codecs/Codec';
import type { DecodedNode } from '../codecs/DecodedNode';
import { SchemaBuilder, SchemaNode } from './SchemaBuilder';

/**
 * High-level codec that wraps a schema definition.
 * Encodes values to Uint8Array and decodes Uint8Array back to values.
 */
export class SchemaCodec {
  private readonly _codec: Codec<unknown>;

  constructor(schema: SchemaNode) {
    this._codec = SchemaBuilder.build(schema);
  }

  /** Encode a value to a Uint8Array. */
  encode(value: unknown): Uint8Array {
    const buffer = BitBuffer.alloc();
    this._codec.encode(buffer, value);
    return buffer.toUint8Array();
  }

  /** Encode a value and return hex string. */
  encodeToHex(value: unknown): string {
    const buffer = BitBuffer.alloc();
    this._codec.encode(buffer, value);
    return buffer.toHex();
  }

  /** Decode a Uint8Array back to a value. */
  decode(data: Uint8Array): unknown {
    const buffer = BitBuffer.from(data);
    return this._codec.decode(buffer);
  }

  /** Decode a hex string back to a value. */
  decodeFromHex(hex: string): unknown {
    const bytes = new Uint8Array(
      hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
    );
    return this.decode(bytes);
  }

  /** Decode a Uint8Array with full metadata tree. */
  decodeWithMetadata(data: Uint8Array): DecodedNode {
    const buffer = BitBuffer.from(data);
    return this._codec.decodeWithMetadata(buffer);
  }

  /** Decode a hex string with full metadata tree. */
  decodeFromHexWithMetadata(hex: string): DecodedNode {
    const bytes = new Uint8Array(
      hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
    );
    return this.decodeWithMetadata(bytes);
  }

  /** Access the underlying built codec. */
  get codec(): Codec<unknown> {
    return this._codec;
  }
}
