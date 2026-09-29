import type { Codec } from '../codecs/Codec.js';
import { SchemaBuilder } from '../schema/SchemaBuilder.js';
import { SchemaCodec } from '../schema/SchemaCodec.js';
import type { SchemaNode, SchemaRegistry } from '../schema/SchemaNode.js';
import type { TypedCodec } from '../schema/TypedCodec.js';
import type { AnySchema, InputOf, NodeOf, TypeOf } from './Schema.js';

/** A named set of DSL schemas, the DSL's equivalent of a {@link SchemaRegistry}. */
export type SchemaModule = Record<string, AnySchema>;

/** The codec produced for one DSL schema. */
export type CodecOf<S> = TypedCodec<TypeOf<S>, InputOf<S>, NodeOf<S>>;

/** A codec per entry of a {@link SchemaModule}. */
export type CodecsOf<M extends SchemaModule> = { [K in keyof M]: CodecOf<M[K]> };

/**
 * The interchange representation of a DSL schema — the same `SchemaNode` shape
 * the ASN.1 parser produces and the code generator consumes.
 */
export function toSchemaNode(schema: AnySchema): SchemaNode {
  return schema.node;
}

/** The interchange representation of a whole {@link SchemaModule}. */
export function toSchemaRegistry(module: SchemaModule): SchemaRegistry {
  const registry: SchemaRegistry = {};
  for (const [name, schema] of Object.entries(module)) {
    registry[name] = schema.node;
  }
  return registry;
}

/**
 * Build a codec from a single DSL schema.
 *
 * The schema may not contain `asn.ref(...)` — there is nothing to resolve it
 * against. Use {@link compile} for schemas that reference each other.
 */
export function codec<S extends AnySchema>(schema: S): CodecOf<S> {
  return new SchemaCodec(schema.node) as unknown as CodecOf<S>;
}

/**
 * Build a codec for every schema in a module, resolving `asn.ref(...)` between
 * them.
 *
 * ```typescript
 * const codecs = asn.compile({ Person, Animal });
 * const person = codecs.Person.decodeFromHex(hex);
 * ```
 */
export function compile<M extends SchemaModule>(module: M): CodecsOf<M> {
  const registry = toSchemaRegistry(module);
  const built = SchemaBuilder.buildAll(registry) as Record<string, Codec<unknown>>;
  const codecs: Record<string, unknown> = {};
  for (const [name, node] of Object.entries(registry)) {
    codecs[name] = new SchemaCodec(node, built[name]);
  }
  return codecs as CodecsOf<M>;
}
