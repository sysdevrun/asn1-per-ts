import type { DecodedNode } from './DecodedNode';
import { BooleanCodec } from './BooleanCodec';
import { IntegerCodec } from './IntegerCodec';
import { EnumeratedCodec } from './EnumeratedCodec';
import { BitStringCodec } from './BitStringCodec';
import { OctetStringCodec } from './OctetStringCodec';
import { UTF8StringCodec } from './UTF8StringCodec';
import { ObjectIdentifierCodec } from './ObjectIdentifierCodec';
import { NullCodec } from './NullCodec';
import { SequenceCodec } from './SequenceCodec';
import { SequenceOfCodec } from './SequenceOfCodec';
import { ChoiceCodec } from './ChoiceCodec';

/**
 * Walk a DecodedNode tree and reconstruct the plain JS object
 * identical to decode() output. Dispatches on the codec stored
 * in each node's metadata using instanceof checks.
 */
export function stripMetadata(node: DecodedNode): unknown {
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
