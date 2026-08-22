import { BitBuffer } from '../BitBuffer.js';
import { RawBytes } from '../RawBytes.js';
import { Codec } from '../codecs/Codec.js';
import { encodeValue } from '../helpers.js';
import { SchemaBuilder } from './SchemaBuilder.js';
import type { SchemaNode, SchemaRegistry } from './SchemaNode.js';
import type { Infer, InferInput, InferMetadata } from './Infer.js';

/** Convert a hex string to the bytes it represents. */
function hexToBytes(hex: string): Uint8Array {
  const pairs = hex.match(/.{1,2}/g);
  if (!pairs) return new Uint8Array(0);
  return new Uint8Array(pairs.map(byte => parseInt(byte, 16)));
}

/**
 * High-level codec that wraps a schema definition.
 * Encodes values to Uint8Array and decodes Uint8Array back to values.
 *
 * The decoded type is derived from the schema's literal type, so TypeScript
 * knows the shape of what comes out of `decode()`:
 *
 * ```typescript
 * const codec = new SchemaCodec({
 *   type: 'SEQUENCE',
 *   fields: [
 *     { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
 *     { name: 'active', schema: { type: 'BOOLEAN' } },
 *   ],
 * });
 *
 * const value = codec.decodeFromHex('2a80');
 * //    ^? { id: number; active: boolean }
 * ```
 *
 * When the schema is only known at runtime (parsed from JSON, produced by the
 * ASN.1 parser), `S` stays the wide `SchemaNode` union and every method keeps
 * the `unknown` types the API had before.
 *
 * @typeParam S - The schema, with its literal type preserved.
 * @typeParam R - Registry used to resolve `$ref` nodes. Bound by
 * {@link createCodecs}; `$ref` is unresolvable for a standalone codec.
 */
export class SchemaCodec<
  const S extends SchemaNode = SchemaNode,
  R extends SchemaRegistry = Record<never, never>,
> {
  private readonly _schema: S;
  private readonly _codec: Codec<unknown>;

  /**
   * @param schema - The schema to encode and decode.
   * @param prebuiltCodec - Internal. A codec already built for `schema`, used
   * by {@link createCodecs} so that `$ref` nodes resolve against a registry.
   */
  constructor(schema: S, prebuiltCodec?: Codec<unknown>) {
    this._schema = schema;
    this._codec = prebuiltCodec ?? SchemaBuilder.build(schema);
  }

  /** Encode a value to a Uint8Array. */
  encode(value: InferInput<S, R>): Uint8Array {
    const buffer = BitBuffer.alloc();
    encodeValue(buffer, this._codec, value);
    return buffer.toUint8Array();
  }

  /** Encode a value and return a RawBytes with exact bit-length. */
  encodeToRawBytes(value: InferInput<S, R>): RawBytes {
    const buffer = BitBuffer.alloc();
    encodeValue(buffer, this._codec, value);
    return new RawBytes(buffer.toUint8Array(), buffer.bitLength);
  }

  /** Encode a value and return hex string. */
  encodeToHex(value: InferInput<S, R>): string {
    const buffer = BitBuffer.alloc();
    encodeValue(buffer, this._codec, value);
    return buffer.toHex();
  }

  /** Decode a Uint8Array back to a value. */
  decode(data: Uint8Array): Infer<S, R> {
    const buffer = BitBuffer.from(data);
    return this._codec.decode(buffer) as Infer<S, R>;
  }

  /** Decode a hex string back to a value. */
  decodeFromHex(hex: string): Infer<S, R> {
    return this.decode(hexToBytes(hex));
  }

  /** Decode a Uint8Array with full metadata tree. */
  decodeWithMetadata(data: Uint8Array): InferMetadata<S, R> {
    const buffer = BitBuffer.from(data);
    return this._codec.decodeWithMetadata(buffer) as InferMetadata<S, R>;
  }

  /** Decode a hex string with full metadata tree. */
  decodeFromHexWithMetadata(hex: string): InferMetadata<S, R> {
    return this.decodeWithMetadata(hexToBytes(hex));
  }

  /** The schema this codec was built from. */
  get schema(): S {
    return this._schema;
  }

  /** Access the underlying built codec. */
  get codec(): Codec<Infer<S, R>, InferInput<S, R>> {
    return this._codec as Codec<Infer<S, R>, InferInput<S, R>>;
  }
}

/**
 * Identity function that pins a schema's literal type.
 *
 * Use it when a schema is declared separately from the codec, so that
 * {@link Infer} can still read the literal types — the alternative is `as const`,
 * which also makes the object deeply readonly.
 *
 * ```typescript
 * const Ticket = defineSchema({
 *   type: 'SEQUENCE',
 *   fields: [{ name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } }],
 * });
 *
 * type Ticket = Infer<typeof Ticket>; // { id: number }
 * ```
 */
export function defineSchema<const S extends SchemaNode>(schema: S): S {
  return schema;
}

/** Identity function that pins the literal types of a whole schema registry. */
export function defineSchemas<const R extends SchemaRegistry>(schemas: R): R {
  return schemas;
}

/**
 * Build a typed {@link SchemaCodec} from a schema.
 *
 * Equivalent to `new SchemaCodec(schema)`; provided so codecs can be created
 * without `new` and so the inferred type reads naturally in editors.
 */
export function createCodec<const S extends SchemaNode>(schema: S): SchemaCodec<S> {
  return new SchemaCodec(schema);
}

/** A typed codec for every schema in a registry, with `$ref` resolved. */
export type SchemaCodecs<R extends SchemaRegistry> = {
  [K in keyof R]: R[K] extends SchemaNode ? SchemaCodec<R[K], R> : never;
};

/**
 * Build a typed {@link SchemaCodec} for every schema in a registry.
 *
 * Unlike {@link createCodec}, `$ref` nodes are resolved — both at runtime and
 * in the inferred types — against the other schemas in the registry.
 *
 * ```typescript
 * const codecs = createCodecs({
 *   Person: {
 *     type: 'SEQUENCE',
 *     fields: [
 *       { name: 'name', schema: { type: 'UTF8String' } },
 *       { name: 'pet', schema: { type: '$ref', ref: 'Animal' }, optional: true },
 *     ],
 *   },
 *   Animal: { type: 'SEQUENCE', fields: [{ name: 'legs', schema: { type: 'INTEGER', min: 0, max: 8 } }] },
 * });
 *
 * const person = codecs.Person.decodeFromHex(hex);
 * //    ^? { name: string; pet?: { legs: number } }
 * ```
 */
export function createCodecs<const R extends SchemaRegistry>(schemas: R): SchemaCodecs<R> {
  const built = SchemaBuilder.buildAll(schemas) as Record<string, Codec<unknown>>;
  const result: Record<string, SchemaCodec<SchemaNode, SchemaRegistry>> = {};
  for (const [name, schema] of Object.entries(schemas)) {
    result[name] = new SchemaCodec(schema, built[name]);
  }
  return result as SchemaCodecs<R>;
}
