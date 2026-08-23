import type { BitStringValue } from '../codecs/BitStringCodec.js';
import type { DecodedNode } from '../codecs/DecodedNode.js';
import type { SchemaAlternative, SchemaField, SchemaNode } from '../schema/SchemaNode.js';
import type { Simplify } from '../typeUtils.js';
import {
  makeSchema,
  type AnySchema,
  type InputOf,
  type NodeOf,
  type Schema,
  type TypeOf,
} from './Schema.js';

/* -------------------------------------------------------------------------
 * Field/alternative maps
 * ---------------------------------------------------------------------- */

/** A map of field name to schema. Declaration order is the PER encoding order. */
export type Fields = Record<string, AnySchema>;
/** A map of alternative name to schema. Declaration order is the CHOICE index order. */
export type Alternatives = Record<string, AnySchema>;

type IsOptionalField<F> = F extends { readonly __optional: true } ? true : false;
type IsDefaultField<F> = F extends { readonly __default: true } ? true : false;
/** Omittable when encoding: OPTIONAL fields and DEFAULT fields alike. */
type IsOmittable<F> = IsOptionalField<F> extends true ? true : IsDefaultField<F>;

type SequenceOut<F extends Fields, E extends Fields> = Simplify<
  { [K in keyof F as IsOptionalField<F[K]> extends true ? never : K]: TypeOf<F[K]> } & {
    [K in keyof F as IsOptionalField<F[K]> extends true ? K : never]?: TypeOf<F[K]>;
  } & { [K in keyof E]?: TypeOf<E[K]> }
>;

type SequenceIn<F extends Fields, E extends Fields> = Simplify<
  { [K in keyof F as IsOmittable<F[K]> extends true ? never : K]: InputOf<F[K]> } & {
    [K in keyof F as IsOmittable<F[K]> extends true ? K : never]?: InputOf<F[K]>;
  } & { [K in keyof E]?: InputOf<E[K]> }
>;

/** Absent OPTIONAL fields still occupy a node in the metadata tree. */
type MaybeAbsentNode<N> = N extends DecodedNode<infer V> ? DecodedNode<V | undefined> : N;

type SequenceNode<F extends Fields, E extends Fields> = DecodedNode<
  Simplify<
    {
      [K in keyof F]: IsOptionalField<F[K]> extends true
        ? MaybeAbsentNode<NodeOf<F[K]>>
        : NodeOf<F[K]>;
    } & { [K in keyof E]: MaybeAbsentNode<NodeOf<E[K]>> }
  >
>;

type ChoiceOut<A extends Alternatives, E extends Alternatives> =
  | { [K in keyof A]: { key: K; value: TypeOf<A[K]> } }[keyof A]
  | { [K in keyof E]: { key: K; value: TypeOf<E[K]> } }[keyof E];

type ChoiceIn<A extends Alternatives, E extends Alternatives> =
  | { [K in keyof A]: { key: K; value: InputOf<A[K]> } }[keyof A]
  | { [K in keyof E]: { key: K; value: InputOf<E[K]> } }[keyof E];

type ChoiceNode<A extends Alternatives, E extends Alternatives> = DecodedNode<
  | { [K in keyof A]: { key: K; value: NodeOf<A[K]> } }[keyof A]
  | { [K in keyof E]: { key: K; value: NodeOf<E[K]> } }[keyof E]
>;

/* -------------------------------------------------------------------------
 * Options
 * ---------------------------------------------------------------------- */

/** Size constraint shared by the sized types. */
export interface SizeOptions {
  fixedSize?: number;
  minSize?: number;
  maxSize?: number;
  extensible?: boolean;
}

/** INTEGER value range. */
export interface IntegerOptions {
  min?: number;
  max?: number;
  extensible?: boolean;
}

/** Character string constraints. */
export interface StringOptions extends SizeOptions {
  alphabet?: string;
}

/** Extension additions for SEQUENCE and CHOICE. */
export interface ExtensionOptions<E extends Fields> {
  /**
   * Fields after the `...` extension marker. Passing `{}` marks the type
   * extensible without declaring any addition.
   */
  extensions: E;
}

const NO_EXTENSIONS = {} as const;

/**
 * Object keys that JavaScript reorders. ASN.1 identifiers must start with a
 * lowercase letter so these cannot occur in a valid spec, but a hand-written
 * DSL schema could hit it — and silently reordered fields would produce a
 * wrong encoding rather than an error.
 */
function assertOrderedKeys(names: string[], what: string): void {
  for (const name of names) {
    if (String(Number(name)) === name) {
      throw new Error(
        `${what} name '${name}' is an array index: JavaScript would reorder it ` +
        `ahead of the other keys and change the PER encoding order. Rename it.`,
      );
    }
  }
}

function toFieldNodes(fields: Fields, what: string): SchemaField[] {
  const names = Object.keys(fields);
  assertOrderedKeys(names, what);
  return names.map(name => {
    const schema = fields[name] as AnySchema & {
      __optional?: true;
      __default?: true;
      __defaultValue?: unknown;
    };
    const field: SchemaField = { name, schema: schema.node };
    if (schema.__optional) field.optional = true;
    if (schema.__default) field.defaultValue = schema.__defaultValue;
    return field;
  });
}

function toAlternativeNodes(alternatives: Alternatives, what: string): SchemaAlternative[] {
  const names = Object.keys(alternatives);
  assertOrderedKeys(names, what);
  return names.map(name => ({ name, schema: alternatives[name].node }));
}

/* -------------------------------------------------------------------------
 * Builders
 * ---------------------------------------------------------------------- */

/** BOOLEAN. */
export function boolean(): Schema<boolean> {
  return makeSchema({ type: 'BOOLEAN' });
}

/** NULL. */
function nullType(): Schema<null> {
  return makeSchema({ type: 'NULL' });
}

/** INTEGER, optionally constrained to a range. */
export function integer(options: IntegerOptions = {}): Schema<number> {
  return makeSchema({ type: 'INTEGER', ...options });
}

/** ENUMERATED. The decoded type is the union of the value names. */
export function enumerated<const V extends readonly string[]>(values: V): Schema<V[number]>;
export function enumerated<const V extends readonly string[], const E extends readonly string[]>(
  values: V,
  options: { extensionValues: E },
): Schema<V[number] | E[number]>;
export function enumerated(
  values: readonly string[],
  options?: { extensionValues: readonly string[] },
): Schema<string> {
  return makeSchema({ type: 'ENUMERATED', values, extensionValues: options?.extensionValues });
}

/** BIT STRING. */
export function bitString(options: SizeOptions = {}): Schema<BitStringValue> {
  return makeSchema({ type: 'BIT STRING', ...options });
}

/** OCTET STRING. */
export function octetString(options: SizeOptions = {}): Schema<Uint8Array> {
  return makeSchema({ type: 'OCTET STRING', ...options });
}

/** OBJECT IDENTIFIER, decoded as dot-notation. */
export function objectIdentifier(): Schema<string> {
  return makeSchema({ type: 'OBJECT IDENTIFIER' });
}

/** IA5String. */
export function ia5String(options: StringOptions = {}): Schema<string> {
  return makeSchema({ type: 'IA5String', ...options });
}

/** VisibleString. */
export function visibleString(options: StringOptions = {}): Schema<string> {
  return makeSchema({ type: 'VisibleString', ...options });
}

/** UTF8String. */
export function utf8String(options: StringOptions = {}): Schema<string> {
  return makeSchema({ type: 'UTF8String', ...options });
}

/**
 * SEQUENCE. Field declaration order is the PER encoding order.
 *
 * ```typescript
 * const Ticket = asn.sequence({
 *   id: asn.integer({ min: 0, max: 255 }),
 *   nickname: asn.ia5String().optional(),
 *   version: asn.integer({ min: 0, max: 10 }).default(1),
 * });
 * ```
 */
export function sequence<F extends Fields>(
  fields: F,
): Schema<SequenceOut<F, {}>, SequenceIn<F, {}>, SequenceNode<F, {}>>;
export function sequence<F extends Fields, E extends Fields>(
  fields: F,
  options: ExtensionOptions<E>,
): Schema<SequenceOut<F, E>, SequenceIn<F, E>, SequenceNode<F, E>>;
export function sequence(fields: Fields, options?: ExtensionOptions<Fields>): AnySchema {
  const node: SchemaNode = { type: 'SEQUENCE', fields: toFieldNodes(fields, 'SEQUENCE field') };
  if (options) {
    (node as { extensionFields?: SchemaField[] }).extensionFields = toFieldNodes(
      options.extensions,
      'SEQUENCE extension field',
    );
  }
  return makeSchema(node);
}

/** SEQUENCE OF. */
export function sequenceOf<S extends AnySchema>(
  item: S,
  options: SizeOptions = {},
): Schema<TypeOf<S>[], InputOf<S>[], DecodedNode<NodeOf<S>[]>> {
  return makeSchema({ type: 'SEQUENCE OF', item: item.node, ...options });
}

/**
 * CHOICE. Alternative declaration order is the PER index order.
 *
 * Decodes to a discriminated union `{ key, value }`, so narrowing on `key`
 * narrows `value`.
 */
export function choice<A extends Alternatives>(
  alternatives: A,
): Schema<ChoiceOut<A, {}>, ChoiceIn<A, {}>, ChoiceNode<A, {}>>;
export function choice<A extends Alternatives, E extends Alternatives>(
  alternatives: A,
  options: ExtensionOptions<E>,
): Schema<ChoiceOut<A, E>, ChoiceIn<A, E>, ChoiceNode<A, E>>;
export function choice(alternatives: Alternatives, options?: ExtensionOptions<Alternatives>): AnySchema {
  const node: SchemaNode = {
    type: 'CHOICE',
    alternatives: toAlternativeNodes(alternatives, 'CHOICE alternative'),
  };
  if (options) {
    (node as { extensionAlternatives?: SchemaAlternative[] }).extensionAlternatives =
      toAlternativeNodes(options.extensions, 'CHOICE extension alternative');
  }
  return makeSchema(node);
}

/**
 * A reference to another schema in the same registry, by name.
 *
 * TypeScript cannot infer a recursive type, so name it once as an interface and
 * hand it to `ref` — the surrounding schema then infers from that, and needs no
 * annotation of its own:
 *
 * ```typescript
 * interface Tree { value: number; children: Tree[] }
 *
 * const Tree = asn.sequence({
 *   value: asn.integer({ min: 0, max: 255 }),
 *   children: asn.sequenceOf(asn.ref<Tree>('Tree')),
 * });
 *
 * const codecs = asn.compile({ Tree });
 * ```
 *
 * The name must match the key used in {@link ./compile.js#compile | compile}.
 */
export function ref<T, TIn = T>(name: string): Schema<T, TIn, DecodedNode<T>> {
  return makeSchema({ type: '$ref', ref: name });
}

export { nullType as null };
