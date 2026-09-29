import type { DecodedNode } from './DecodedNode.js';
import type { Simplify } from '../typeUtils.js';
import { BooleanCodec } from './BooleanCodec.js';
import { IntegerCodec } from './IntegerCodec.js';
import { EnumeratedCodec } from './EnumeratedCodec.js';
import { BitStringCodec } from './BitStringCodec.js';
import { OctetStringCodec } from './OctetStringCodec.js';
import { UTF8StringCodec } from './UTF8StringCodec.js';
import { ObjectIdentifierCodec } from './ObjectIdentifierCodec.js';
import { NullCodec } from './NullCodec.js';
import { SequenceCodec } from './SequenceCodec.js';
import { SequenceOfCodec } from './SequenceOfCodec.js';
import { ChoiceCodec } from './ChoiceCodec.js';

/** Any node, regardless of the shape of its value. */
type AnyNode = DecodedNode<unknown>;

/**
 * The plain value type that {@link stripMetadata} reconstructs from the node
 * type `N`. For a tree produced by
 * {@link ../schema/Infer.js#InferMetadata | InferMetadata} this is the same
 * type {@link ../schema/Infer.js#Infer | Infer} gives for the schema.
 */
export type Stripped<N> = N extends DecodedNode<infer V> ? StrippedValue<V> : never;

type StrippedValue<V> = V extends readonly AnyNode[]
  ? { -readonly [I in keyof V]: Stripped<V[I]> }
  : V extends { key: infer K; value: infer C extends AnyNode }
    ? { key: K; value: Stripped<C> }
    : V extends Record<string, AnyNode>
      ? StrippedFields<V>
      : V;

/** Absent OPTIONAL fields are dropped, so their keys become optional. */
type StrippedFields<V extends Record<string, AnyNode>> = Simplify<
  { [K in keyof V as undefined extends NodeValue<V[K]> ? never : K]: Stripped<V[K]> } & {
    [K in keyof V as undefined extends NodeValue<V[K]> ? K : never]?: Stripped<V[K]>;
  }
>;

type NodeValue<N> = N extends DecodedNode<infer V> ? V : never;

/**
 * Walk a DecodedNode tree and reconstruct the plain JS object
 * identical to decode() output. Dispatches on the codec stored
 * in each node's metadata using instanceof checks.
 *
 * The return type is derived from the node type, so stripping a tree decoded
 * from a typed schema yields the same type as `decode()`.
 */
export function stripMetadata<N extends AnyNode>(node: N): Stripped<N>;
export function stripMetadata(node: AnyNode): unknown;
export function stripMetadata(node: AnyNode): unknown {
  const { value, meta } = node;
  const codec = meta.codec;

  if (
    codec instanceof BooleanCodec ||
    codec instanceof IntegerCodec ||
    codec instanceof EnumeratedCodec ||
    codec instanceof BitStringCodec ||
    codec instanceof OctetStringCodec ||
    codec instanceof UTF8StringCodec ||
    codec instanceof ObjectIdentifierCodec ||
    codec instanceof NullCodec
  ) {
    return value;
  }

  if (codec instanceof SequenceCodec) {
    const fields = value as Record<string, DecodedNode>;
    const result: Record<string, unknown> = {};
    for (const [k, child] of Object.entries(fields)) {
      if (child.meta.optional && !child.meta.present && !child.meta.isDefault) {
        continue; // match decode() behavior: key not set
      }
      result[k] = stripMetadata(child);
    }
    return result;
  }

  if (codec instanceof SequenceOfCodec) {
    const items = value as DecodedNode[];
    return items.map(item => stripMetadata(item));
  }

  if (codec instanceof ChoiceCodec) {
    const choice = value as { key: string; value: DecodedNode };
    return { key: choice.key, value: stripMetadata(choice.value) };
  }

  throw new Error(
    `stripMetadata: unhandled codec type: ${codec.constructor.name}`
  );
}
