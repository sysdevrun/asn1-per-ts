import { Codec } from '../codecs/Codec';
import { BooleanCodec } from '../codecs/BooleanCodec';
import { NullCodec } from '../codecs/NullCodec';
import { IntegerCodec } from '../codecs/IntegerCodec';
import { EnumeratedCodec } from '../codecs/EnumeratedCodec';
import { BitStringCodec } from '../codecs/BitStringCodec';
import { OctetStringCodec } from '../codecs/OctetStringCodec';
import { UTF8StringCodec } from '../codecs/UTF8StringCodec';
import { ChoiceCodec } from '../codecs/ChoiceCodec';
import { SequenceCodec } from '../codecs/SequenceCodec';
import { SequenceOfCodec } from '../codecs/SequenceOfCodec';

/**
 * JSON-serializable schema definition for any ASN.1 type.
 */
export type SchemaNode =
  | { type: 'BOOLEAN' }
  | { type: 'NULL' }
  | { type: 'INTEGER'; min?: number; max?: number; extensible?: boolean }
  | { type: 'ENUMERATED'; values: string[]; extensionValues?: string[] }
  | { type: 'BIT STRING'; fixedSize?: number; minSize?: number; maxSize?: number; extensible?: boolean }
  | { type: 'OCTET STRING'; fixedSize?: number; minSize?: number; maxSize?: number; extensible?: boolean }
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
      alternatives: Array<{ name: string; schema: SchemaNode }>;
      extensionAlternatives?: Array<{ name: string; schema: SchemaNode }>;
    }
  | {
      type: 'SEQUENCE';
      fields: Array<{
        name: string;
        schema: SchemaNode;
        optional?: boolean;
        defaultValue?: unknown;
      }>;
      extensionFields?: Array<{
        name: string;
        schema: SchemaNode;
        optional?: boolean;
        defaultValue?: unknown;
      }>;
    }
  | {
      type: 'SEQUENCE OF';
      item: SchemaNode;
      fixedSize?: number;
      minSize?: number;
      maxSize?: number;
      extensible?: boolean;
    };

/**
 * Builds a Codec from a JSON schema definition.
 */
export class SchemaBuilder {
  /** Build a Codec from a schema node definition. */
  static build(node: SchemaNode): Codec<unknown> {
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
            codec: SchemaBuilder.build(a.schema),
          })),
          extensionAlternatives: node.extensionAlternatives?.map(a => ({
            name: a.name,
            codec: SchemaBuilder.build(a.schema),
          })),
        });

      case 'SEQUENCE':
        return new SequenceCodec({
          fields: node.fields.map(f => ({
            name: f.name,
            codec: SchemaBuilder.build(f.schema),
            optional: f.optional,
            defaultValue: f.defaultValue,
          })),
          extensionFields: node.extensionFields?.map(f => ({
            name: f.name,
            codec: SchemaBuilder.build(f.schema),
            optional: f.optional,
            defaultValue: f.defaultValue,
          })),
        });

      case 'SEQUENCE OF':
        return new SequenceOfCodec({
          itemCodec: SchemaBuilder.build(node.item),
          fixedSize: node.fixedSize,
          minSize: node.minSize,
          maxSize: node.maxSize,
          extensible: node.extensible,
        });

      default:
        throw new Error(`Unknown schema type: ${(node as { type: string }).type}`);
    }
  }

  /** Parse a JSON string into a SchemaNode and build the codec. */
  static fromJSON(json: string): Codec<unknown> {
    const node = JSON.parse(json) as SchemaNode;
    return SchemaBuilder.build(node);
  }
}
