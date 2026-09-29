/**
 * The `asn` builder DSL.
 *
 * An alternative front-end to the same engine: schemas are built from
 * functions rather than object literals, so the TypeScript types ride in the
 * value's type parameters instead of being recomputed from literal types.
 * That removes the widening traps of the literal API and produces far shorter
 * type-error messages.
 *
 * Both front-ends compile to the same `SchemaNode` interchange format and hand
 * back the same {@link ../schema/TypedCodec.js#TypedCodec | TypedCodec}.
 *
 * ```typescript
 * import { asn } from 'asn1-per-ts';
 *
 * const Ticket = asn.sequence({
 *   id: asn.integer({ min: 0, max: 255 }),
 *   status: asn.enumerated(['pending', 'approved']),
 *   nickname: asn.ia5String({ minSize: 1, maxSize: 32 }).optional(),
 * });
 *
 * const codec = asn.codec(Ticket);
 * const value = codec.decodeFromHex(hex);
 * //    ^? { id: number; status: 'pending' | 'approved'; nickname?: string }
 * ```
 */
export * as asn from './namespace.js';
export type {
  AnySchema,
  DefaultSchema,
  InputOf,
  NodeOf,
  OptionalSchema,
  Schema,
  SchemaFor,
  TypeOf,
} from './Schema.js';
export type { CodecOf, CodecsOf, SchemaModule } from './compile.js';
export type {
  Alternatives,
  ExtensionOptions,
  Fields,
  IntegerOptions,
  SizeOptions,
  StringOptions,
} from './asn.js';
