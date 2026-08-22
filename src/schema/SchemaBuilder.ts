import { BitBuffer } from '../BitBuffer.js';
import { Codec } from '../codecs/Codec.js';
import type { DecodedNode } from '../codecs/DecodedNode.js';
import { BooleanCodec } from '../codecs/BooleanCodec.js';
import { NullCodec } from '../codecs/NullCodec.js';
import { IntegerCodec } from '../codecs/IntegerCodec.js';
import { EnumeratedCodec } from '../codecs/EnumeratedCodec.js';
import { BitStringCodec } from '../codecs/BitStringCodec.js';
import { OctetStringCodec } from '../codecs/OctetStringCodec.js';
import { UTF8StringCodec } from '../codecs/UTF8StringCodec.js';
import { ChoiceCodec } from '../codecs/ChoiceCodec.js';
import { SequenceCodec } from '../codecs/SequenceCodec.js';
import { SequenceOfCodec } from '../codecs/SequenceOfCodec.js';
import { ObjectIdentifierCodec } from '../codecs/ObjectIdentifierCodec.js';
import type { SchemaNode, SchemaRegistry } from './SchemaNode.js';
import type { Infer, InferInput } from './Infer.js';

export type { SchemaNode, SchemaRegistry, SchemaField, SchemaAlternative } from './SchemaNode.js';

/**
 * A codec that lazily resolves its target. Used for recursive type references ($ref).
 */
class LazyCodec implements Codec<unknown> {
  private _resolved: Codec<unknown> | null = null;
  private readonly _resolver: () => Codec<unknown>;

  constructor(resolver: () => Codec<unknown>) {
    this._resolver = resolver;
  }

  private get codec(): Codec<unknown> {
    if (!this._resolved) {
      this._resolved = this._resolver();
    }
    return this._resolved;
  }

  encode(buffer: BitBuffer, value: unknown): void {
    this.codec.encode(buffer, value);
  }

  decode(buffer: BitBuffer): unknown {
    return this.codec.decode(buffer);
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    return this.codec.decodeWithMetadata(buffer);
  }
}

/** How a `$ref` node is turned into a codec. */
type RefResolver = (ref: string) => Codec<unknown>;

const throwOnRef: RefResolver = ref => {
  throw new Error(
    `Cannot resolve $ref "${ref}" without a schema registry. ` +
    `Use SchemaBuilder.buildAll() for schemas containing $ref nodes.`
  );
};

/** Build a codec for one node, delegating `$ref` handling to the resolver. */
function buildNode(node: SchemaNode, resolveRef: RefResolver): Codec<unknown> {
  switch (node.type) {
    case 'BOOLEAN':
      return new BooleanCodec();

    case 'NULL':
      return new NullCodec();

    case 'INTEGER':
      return new IntegerCodec({
        min: node.min,
        max: node.max,
        extensible: node.extensible,
      });

    case 'ENUMERATED':
      return new EnumeratedCodec({
        values: node.values,
        extensionValues: node.extensionValues,
      });

    case 'BIT STRING':
      return new BitStringCodec({
        fixedSize: node.fixedSize,
        minSize: node.minSize,
        maxSize: node.maxSize,
        extensible: node.extensible,
      });

    case 'OCTET STRING':
      return new OctetStringCodec({
        fixedSize: node.fixedSize,
        minSize: node.minSize,
        maxSize: node.maxSize,
        extensible: node.extensible,
      });

    case 'OBJECT IDENTIFIER':
      return new ObjectIdentifierCodec();

    case 'IA5String':
    case 'VisibleString':
    case 'UTF8String':
      return new UTF8StringCodec({
        type: node.type,
        alphabet: node.alphabet,
        fixedSize: node.fixedSize,
        minSize: node.minSize,
        maxSize: node.maxSize,
        extensible: node.extensible,
      });

    case 'CHOICE':
      return new ChoiceCodec({
        alternatives: node.alternatives.map(a => ({
          name: a.name,
          codec: buildNode(a.schema, resolveRef),
        })),
        extensionAlternatives: node.extensionAlternatives?.map(a => ({
          name: a.name,
          codec: buildNode(a.schema, resolveRef),
        })),
      });

    case 'SEQUENCE':
      return new SequenceCodec({
        fields: node.fields.map(f => ({
          name: f.name,
          codec: buildNode(f.schema, resolveRef),
          optional: f.optional,
          defaultValue: f.defaultValue,
        })),
        extensionFields: node.extensionFields?.map(f => ({
          name: f.name,
          codec: buildNode(f.schema, resolveRef),
          optional: f.optional,
          defaultValue: f.defaultValue,
        })),
      });

    case 'SEQUENCE OF':
      return new SequenceOfCodec({
        itemCodec: buildNode(node.item, resolveRef),
        fixedSize: node.fixedSize,
        minSize: node.minSize,
        maxSize: node.maxSize,
        extensible: node.extensible,
      });

    case '$ref':
      return resolveRef(node.ref);

    default:
      throw new Error(`Unknown schema type: ${(node as { type: string }).type}`);
  }
}

/** Codecs for a whole registry, each typed from its own schema. */
export type BuiltCodecs<R extends SchemaRegistry> = {
  [K in keyof R]: R[K] extends SchemaNode ? Codec<Infer<R[K], R>, InferInput<R[K], R>> : never;
};

/**
 * Builds a Codec from a JSON schema definition.
 */
export class SchemaBuilder {
  /**
   * Build a Codec from a schema node definition.
   *
   * The returned codec is typed from the literal type of `node`, so
   * `decode()` yields {@link Infer} of the schema. Pass the schema inline (or
   * declare it with `defineSchema` / `as const`) to keep those literal types.
   */
  static build<const S extends SchemaNode>(node: S): Codec<Infer<S>, InferInput<S>> {
    return buildNode(node, throwOnRef) as Codec<Infer<S>, InferInput<S>>;
  }

  /**
   * Build codecs for all schemas in a registry, resolving $ref nodes lazily.
   * Returns a map of type name to Codec, each typed from its own schema with
   * `$ref` nodes resolved against the registry.
   */
  static buildAll<const R extends SchemaRegistry>(schemas: R): BuiltCodecs<R> {
    const codecs: Record<string, Codec<unknown>> = {};

    const resolveRef: RefResolver = ref =>
      new LazyCodec(() => {
        const target = codecs[ref];
        if (!target) {
          throw new Error(`Unresolved $ref: "${ref}"`);
        }
        return target;
      });

    for (const [name, schema] of Object.entries(schemas)) {
      codecs[name] = buildNode(schema, resolveRef);
    }

    return codecs as BuiltCodecs<R>;
  }

  /**
   * Parse a JSON string into a SchemaNode and build the codec.
   *
   * The schema is only known at runtime, so the decoded type cannot be
   * inferred. Supply it explicitly when you know it.
   */
  static fromJSON<T = unknown, TInput = T>(json: string): Codec<T, TInput> {
    const node = JSON.parse(json) as SchemaNode;
    return buildNode(node, throwOnRef) as Codec<T, TInput>;
  }
}
