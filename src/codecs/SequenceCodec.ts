import { BitBuffer } from '../BitBuffer';
import { Codec } from './Codec';
import type { DecodedNode } from './DecodedNode';
import {
  encodeNormallySmallNumber,
  decodeNormallySmallNumber,
  encodeUnconstrainedLength,
  decodeUnconstrainedLength,
} from '../helpers';

export interface SequenceField {
  /** Field name (used as key in the JS object). */
  name: string;
  /** Codec for this field's type. */
  codec: Codec<unknown>;
  /** Whether this field is OPTIONAL. */
  optional?: boolean;
  /** Default value (implies the field is a DEFAULT field). */
  defaultValue?: unknown;
}

export interface SequenceOptions {
  /** Root component fields, in definition order. */
  fields: readonly SequenceField[];
  /** Extension addition fields, in definition order. */
  extensionFields?: readonly SequenceField[];
}

/**
 * PER unaligned SEQUENCE codec (X.691 §18).
 * Encodes a preamble bitmap for OPTIONAL/DEFAULT fields,
 * then each present component in definition order.
 */
export class SequenceCodec implements Codec<Record<string, unknown>> {
  private readonly rootFields: readonly SequenceField[];
  private readonly extFields: readonly SequenceField[];
  private readonly _extensible: boolean;
  private readonly optionalDefaultFields: number[];

  constructor(options: SequenceOptions) {
    this.rootFields = options.fields;
    this.extFields = options.extensionFields ?? [];
    // Extensible if extensionFields was explicitly provided (even if empty)
    this._extensible = options.extensionFields !== undefined;
    // Indices of root fields that are optional or have defaults
    this.optionalDefaultFields = [];
    for (let i = 0; i < this.rootFields.length; i++) {
      if (this.rootFields[i].optional || this.rootFields[i].defaultValue !== undefined) {
        this.optionalDefaultFields.push(i);
      }
    }
  }

  get extensible(): boolean {
    return this._extensible;
  }

  /** Number of preamble bits (count of optional + default root fields). */
  get preambleBitCount(): number {
    return this.optionalDefaultFields.length;
  }

  encode(buffer: BitBuffer, value: Record<string, unknown>): void {
    // Determine which extension fields are present
    const hasExtensions = this.extensible && this.extFields.some(f => value[f.name] !== undefined);

    // Extension marker bit
    if (this.extensible) {
      buffer.writeBit(hasExtensions ? 1 : 0);
    }

    // Root preamble bitmap
    for (const idx of this.optionalDefaultFields) {
      const field = this.rootFields[idx];
      const fieldValue = value[field.name];
      const isPresent = fieldValue !== undefined && !this.isDefaultValue(field, fieldValue);
      buffer.writeBit(isPresent ? 1 : 0);
    }

    // Encode root components
    let optIdx = 0;
    for (let i = 0; i < this.rootFields.length; i++) {
      const field = this.rootFields[i];
      if (field.optional || field.defaultValue !== undefined) {
        const fieldValue = value[field.name];
        const isPresent = fieldValue !== undefined && !this.isDefaultValue(field, fieldValue);
        optIdx++;
        if (!isPresent) continue;
        field.codec.encode(buffer, fieldValue);
      } else {
        // Mandatory field
        if (value[field.name] === undefined) {
          throw new Error(`Missing mandatory field: '${field.name}'`);
        }
        field.codec.encode(buffer, value[field.name]);
      }
    }

    // Extension additions
    if (hasExtensions) {
      // Encode count of extension fields
      const extCount = this.extFields.length;
      encodeNormallySmallNumber(buffer, extCount - 1);

      // Extension presence bitmap
      for (const field of this.extFields) {
        buffer.writeBit(value[field.name] !== undefined ? 1 : 0);
      }

      // Encode present extension fields as open type
      for (const field of this.extFields) {
        if (value[field.name] !== undefined) {
          const tmp = BitBuffer.alloc();
          field.codec.encode(tmp, value[field.name]);
          const bytes = tmp.toUint8Array();
          encodeUnconstrainedLength(buffer, bytes.length);
          buffer.writeOctets(bytes);
        }
      }
    }
  }

  decode(buffer: BitBuffer): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    // Extension marker bit
    let hasExtensions = false;
    if (this.extensible) {
      hasExtensions = buffer.readBit() === 1;
    }

    // Read root preamble bitmap
    const preamble: boolean[] = [];
    for (let i = 0; i < this.optionalDefaultFields.length; i++) {
      preamble.push(buffer.readBit() === 1);
    }

    // Decode root components
    let optIdx = 0;
    for (let i = 0; i < this.rootFields.length; i++) {
      const field = this.rootFields[i];
      if (field.optional || field.defaultValue !== undefined) {
        const isPresent = preamble[optIdx++];
        if (isPresent) {
          result[field.name] = field.codec.decode(buffer);
        } else if (field.defaultValue !== undefined) {
          result[field.name] = field.defaultValue;
        }
        // If optional and not present, key is not set (undefined)
      } else {
        result[field.name] = field.codec.decode(buffer);
      }
    }

    // Decode extension additions
    if (hasExtensions) {
      const extCount = decodeNormallySmallNumber(buffer) + 1;

      // Read extension presence bitmap
      const extPreamble: boolean[] = [];
      for (let i = 0; i < extCount; i++) {
        extPreamble.push(buffer.readBit() === 1);
      }

      // Decode present extension fields
      for (let i = 0; i < extCount; i++) {
        if (extPreamble[i]) {
          const byteLen = decodeUnconstrainedLength(buffer);
          const bytes = buffer.readOctets(byteLen);
          if (i < this.extFields.length) {
            const tmp = BitBuffer.from(bytes);
            result[this.extFields[i].name] = this.extFields[i].codec.decode(tmp);
          }
          // Unknown extensions are silently skipped
        }
      }
    }

    return result;
  }

  decodeWithMetadata(buffer: BitBuffer): DecodedNode {
    const bitOffset = buffer.offset;
    const fields: Record<string, DecodedNode> = {};

    // Extension marker bit
    let hasExtensions = false;
    if (this.extensible) {
      hasExtensions = buffer.readBit() === 1;
    }

    // Read root preamble bitmap
    const preamble: boolean[] = [];
    for (let i = 0; i < this.optionalDefaultFields.length; i++) {
      preamble.push(buffer.readBit() === 1);
    }

    // Decode root components
    let optIdx = 0;
    for (let i = 0; i < this.rootFields.length; i++) {
      const field = this.rootFields[i];
      if (field.optional || field.defaultValue !== undefined) {
        const isPresent = preamble[optIdx++];
        if (isPresent) {
          const child = field.codec.decodeWithMetadata(buffer);
          child.meta.optional = field.optional;
          child.meta.present = true;
          fields[field.name] = child;
        } else if (field.defaultValue !== undefined) {
          fields[field.name] = {
            value: field.defaultValue,
            meta: {
              bitOffset: buffer.offset,
              bitLength: 0,
              rawBytes: new Uint8Array(0),
              codec: field.codec,
              optional: field.optional,
              present: false,
              isDefault: true,
            },
          };
        } else {
          // OPTIONAL, not present
          fields[field.name] = {
            value: undefined,
            meta: {
              bitOffset: buffer.offset,
              bitLength: 0,
              rawBytes: new Uint8Array(0),
              codec: field.codec,
              optional: true,
              present: false,
            },
          };
        }
      } else {
        // Mandatory
        const child = field.codec.decodeWithMetadata(buffer);
        child.meta.present = true;
        fields[field.name] = child;
      }
    }

    // Decode extension additions
    if (hasExtensions) {
      const extCount = decodeNormallySmallNumber(buffer) + 1;

      // Read extension presence bitmap
      const extPreamble: boolean[] = [];
      for (let i = 0; i < extCount; i++) {
        extPreamble.push(buffer.readBit() === 1);
      }

      // Decode present extension fields
      for (let i = 0; i < extCount; i++) {
        if (extPreamble[i]) {
          const byteLen = decodeUnconstrainedLength(buffer);
          const bytes = buffer.readOctets(byteLen);
          if (i < this.extFields.length) {
            const tmp = BitBuffer.from(bytes);
            const child = this.extFields[i].codec.decodeWithMetadata(tmp);
            child.meta.optional = this.extFields[i].optional;
            child.meta.present = true;
            child.meta.isExtension = true;
            fields[this.extFields[i].name] = child;
          }
          // Unknown extensions are silently skipped
        } else if (i < this.extFields.length) {
          const extField = this.extFields[i];
          fields[extField.name] = {
            value: undefined,
            meta: {
              bitOffset: buffer.offset,
              bitLength: 0,
              rawBytes: new Uint8Array(0),
              codec: extField.codec,
              optional: true,
              present: false,
              isExtension: true,
            },
          };
        }
      }
    }

    const bitLength = buffer.offset - bitOffset;
    return {
      value: fields,
      meta: {
        bitOffset,
        bitLength,
        rawBytes: buffer.extractBits(bitOffset, bitLength),
        codec: this,
      },
    };
  }

  private isDefaultValue(field: SequenceField, value: unknown): boolean {
    if (field.defaultValue === undefined) return false;
    return JSON.stringify(value) === JSON.stringify(field.defaultValue);
  }
}
