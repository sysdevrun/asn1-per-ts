import type { DecodedNode } from './DecodedNode.js';
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
