/**
 * JSON-serializable schema definitions for ASN.1 types.
 *
 * Every collection is typed as a `readonly` array so that schemas written
 * inline in TypeScript (or frozen with `as const`) are assignable without
 * losing their literal types. Literal types are what makes {@link
 * ../schema/Infer.js#Infer | Infer} able to compute the decoded TypeScript
 * type of a schema.
 */

/** A component of a SEQUENCE. */
export interface SchemaField {
  /** Field name, used as the key in the decoded object. */
  name: string;
  /** Schema of the field's type. */
  schema: SchemaNode;
  /** Whether the field is declared OPTIONAL. */
  optional?: boolean;
  /** DEFAULT value; implies the field is a DEFAULT field. */
  defaultValue?: unknown;
}

/** An alternative of a CHOICE. */
export interface SchemaAlternative {
  /** Alternative name, used as the `key` of the decoded choice value. */
  name: string;
  /** Schema of the alternative's type. */
  schema: SchemaNode;
}

/**
 * JSON-serializable schema definition for any ASN.1 type.
 */
export type SchemaNode =
  | { type: 'BOOLEAN' }
  | { type: 'NULL' }
  | { type: 'INTEGER'; min?: number; max?: number; extensible?: boolean }
  | { type: 'ENUMERATED'; values: readonly string[]; extensionValues?: readonly string[] }
  | { type: 'BIT STRING'; fixedSize?: number; minSize?: number; maxSize?: number; extensible?: boolean }
  | { type: 'OCTET STRING'; fixedSize?: number; minSize?: number; maxSize?: number; extensible?: boolean }
  | { type: 'OBJECT IDENTIFIER' }
  | {
      type: 'IA5String' | 'VisibleString' | 'UTF8String';
      alphabet?: string;
      fixedSize?: number;
      minSize?: number;
      maxSize?: number;
      extensible?: boolean;
    }
  | {
      type: 'CHOICE';
      alternatives: readonly SchemaAlternative[];
      extensionAlternatives?: readonly SchemaAlternative[];
    }
  | {
      type: 'SEQUENCE';
      fields: readonly SchemaField[];
      extensionFields?: readonly SchemaField[];
    }
  | {
      type: 'SEQUENCE OF';
      item: SchemaNode;
      fixedSize?: number;
      minSize?: number;
      maxSize?: number;
      extensible?: boolean;
    }
  | { type: '$ref'; ref: string };

/**
 * A map of type name to schema, as produced by
 * {@link ../parser/toSchemaNode.js#convertModuleToSchemaNodes}.
 * `$ref` nodes are resolved against a registry.
 */
export type SchemaRegistry = Record<string, SchemaNode>;
