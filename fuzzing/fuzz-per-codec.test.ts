/**
 * Fuzz tests for PER unaligned encode/decode round-trip.
 *
 * For each codec type, generates random valid values, encodes them,
 * decodes the result, and verifies the output matches the input.
 * This catches serialization/deserialization mismatches, off-by-one
 * bit errors, and constraint handling bugs.
 */

import { BitBuffer } from '../src/BitBuffer';
import { BooleanCodec } from '../src/codecs/BooleanCodec';
import { IntegerCodec } from '../src/codecs/IntegerCodec';
import { EnumeratedCodec } from '../src/codecs/EnumeratedCodec';
import { BitStringCodec } from '../src/codecs/BitStringCodec';
import { OctetStringCodec } from '../src/codecs/OctetStringCodec';
import { UTF8StringCodec } from '../src/codecs/UTF8StringCodec';
import { ObjectIdentifierCodec } from '../src/codecs/ObjectIdentifierCodec';
import { NullCodec } from '../src/codecs/NullCodec';
import { SequenceCodec } from '../src/codecs/SequenceCodec';
import { ChoiceCodec } from '../src/codecs/ChoiceCodec';
import { SequenceOfCodec } from '../src/codecs/SequenceOfCodec';
import { SchemaCodec } from '../src/schema/SchemaCodec';
import { Rng } from './generators/asn1-generator';

const FUZZ_ITERATIONS = Number(process.env.FUZZ_ITERATIONS) || 200;

function roundTrip<T>(codec: { encode(buf: BitBuffer, val: T): void; decode(buf: BitBuffer): T }, value: T): T {
  const buf = BitBuffer.alloc(1024);
  codec.encode(buf, value);
  const encoded = buf.toUint8Array();
  const readBuf = BitBuffer.from(encoded, buf.bitLength);
  return codec.decode(readBuf);
}

// -- Boolean --

describe('PER fuzz: BooleanCodec round-trip', () => {
  it('should round-trip random booleans', () => {
    const codec = new BooleanCodec();
    const rng = new Rng(1);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const val = rng.chance(0.5);
      expect(roundTrip(codec, val)).toBe(val);
    }
  });
});

// -- Integer --

describe('PER fuzz: IntegerCodec round-trip', () => {
  it('should round-trip constrained integers with random ranges', () => {
    const rng = new Rng(2);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const min = rng.int(-10000, 10000);
      const max = min + rng.int(0, 10000);
      const codec = new IntegerCodec({ min, max });
      const value = rng.int(min, max);
      const decoded = roundTrip(codec, value);
      expect(decoded).toBe(value);
    }
  });

  it('should round-trip single-value ranges (0 bits)', () => {
    const rng = new Rng(3);
    for (let i = 0; i < 50; i++) {
      const val = rng.int(-1000, 1000);
      const codec = new IntegerCodec({ min: val, max: val });
      expect(roundTrip(codec, val)).toBe(val);
    }
  });

  it('should round-trip extensible integers within range', () => {
    const rng = new Rng(4);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const min = rng.int(-100, 100);
      const max = min + rng.int(1, 1000);
      const codec = new IntegerCodec({ min, max, extensible: true });
      const value = rng.int(min, max);
      expect(roundTrip(codec, value)).toBe(value);
    }
  });

  it('should round-trip extensible integers outside range', () => {
    const codec = new IntegerCodec({ min: 0, max: 100, extensible: true });
    const rng = new Rng(5);
    for (let i = 0; i < 50; i++) {
      const value = rng.int(101, 10000);
      expect(roundTrip(codec, value)).toBe(value);
    }
    for (let i = 0; i < 50; i++) {
      const value = rng.int(-10000, -1);
      expect(roundTrip(codec, value)).toBe(value);
    }
  });

  it('should round-trip unconstrained integers', () => {
    const codec = new IntegerCodec();
    const rng = new Rng(6);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const value = rng.int(-100000, 100000);
      expect(roundTrip(codec, value)).toBe(value);
    }
  });

  it('should round-trip semi-constrained integers', () => {
    const rng = new Rng(7);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const min = rng.int(-1000, 1000);
      const codec = new IntegerCodec({ min });
      const value = rng.int(min, min + 10000);
      expect(roundTrip(codec, value)).toBe(value);
    }
  });

  it('should round-trip boundary values', () => {
    const boundaries = [
      { min: 0, max: 1 },
      { min: 0, max: 255 },
      { min: 0, max: 256 },
      { min: -128, max: 127 },
      { min: 0, max: 65535 },
      { min: -32768, max: 32767 },
    ];
    for (const { min, max } of boundaries) {
      const codec = new IntegerCodec({ min, max });
      expect(roundTrip(codec, min)).toBe(min);
      expect(roundTrip(codec, max)).toBe(max);
      if (min !== max) {
        expect(roundTrip(codec, min + 1)).toBe(min + 1);
        expect(roundTrip(codec, max - 1)).toBe(max - 1);
      }
    }
  });
});

// -- Enumerated --

describe('PER fuzz: EnumeratedCodec round-trip', () => {
  it('should round-trip random enum selections', () => {
    const rng = new Rng(8);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const numValues = rng.int(1, 20);
      const values = Array.from({ length: numValues }, (_, j) => `val${j}`);
      const codec = new EnumeratedCodec({ values });
      const selected = rng.pick(values);
      expect(roundTrip(codec, selected)).toBe(selected);
    }
  });

  it('should round-trip extensible enums', () => {
    const rng = new Rng(9);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const numRoot = rng.int(1, 10);
      const numExt = rng.int(1, 10);
      const values = Array.from({ length: numRoot }, (_, j) => `root${j}`);
      const extensionValues = Array.from({ length: numExt }, (_, j) => `ext${j}`);
      const codec = new EnumeratedCodec({ values, extensionValues });

      // Root value
      const rootVal = rng.pick(values);
      expect(roundTrip(codec, rootVal)).toBe(rootVal);

      // Extension value
      const extVal = rng.pick(extensionValues);
      expect(roundTrip(codec, extVal)).toBe(extVal);
    }
  });
});

// -- OctetString --

describe('PER fuzz: OctetStringCodec round-trip', () => {
  it('should round-trip fixed-size octet strings', () => {
    const rng = new Rng(10);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const size = rng.int(1, 50);
      const codec = new OctetStringCodec({ fixedSize: size });
      const data = new Uint8Array(size);
      for (let j = 0; j < size; j++) data[j] = rng.int(0, 255);
      const decoded = roundTrip(codec, data);
      expect(decoded).toEqual(data);
    }
  });

  it('should round-trip variable-size octet strings', () => {
    const rng = new Rng(11);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const minSize = rng.int(0, 10);
      const maxSize = minSize + rng.int(1, 50);
      const codec = new OctetStringCodec({ minSize, maxSize });
      const len = rng.int(minSize, maxSize);
      const data = new Uint8Array(len);
      for (let j = 0; j < len; j++) data[j] = rng.int(0, 255);
      const decoded = roundTrip(codec, data);
      expect(decoded).toEqual(data);
    }
  });

  it('should round-trip unconstrained octet strings', () => {
    const rng = new Rng(12);
    const codec = new OctetStringCodec();
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const len = rng.int(0, 100);
      const data = new Uint8Array(len);
      for (let j = 0; j < len; j++) data[j] = rng.int(0, 255);
      const decoded = roundTrip(codec, data);
      expect(decoded).toEqual(data);
    }
  });
});

// -- BitString --

describe('PER fuzz: BitStringCodec round-trip', () => {
  it('should round-trip fixed-size bit strings', () => {
    const rng = new Rng(13);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bitLen = rng.int(1, 64);
      const codec = new BitStringCodec({ fixedSize: bitLen });
      const byteLen = Math.ceil(bitLen / 8);
      const data = new Uint8Array(byteLen);
      for (let j = 0; j < byteLen; j++) data[j] = rng.int(0, 255);
      // Clear trailing bits beyond bitLen
      const trailingBits = byteLen * 8 - bitLen;
      if (trailingBits > 0) {
        data[byteLen - 1] &= (0xFF << trailingBits) & 0xFF;
      }
      const value = { data, bitLength: bitLen };
      const decoded = roundTrip(codec, value);
      expect(decoded.bitLength).toBe(bitLen);
      expect(decoded.data).toEqual(data);
    }
  });

  it('should round-trip variable-size bit strings', () => {
    const rng = new Rng(14);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const minSize = rng.int(0, 8);
      const maxSize = minSize + rng.int(1, 32);
      const codec = new BitStringCodec({ minSize, maxSize });
      const bitLen = rng.int(minSize, maxSize);
      const byteLen = Math.ceil(bitLen / 8) || 0;
      const data = new Uint8Array(byteLen);
      for (let j = 0; j < byteLen; j++) data[j] = rng.int(0, 255);
      if (bitLen > 0) {
        const trailingBits = byteLen * 8 - bitLen;
        if (trailingBits > 0) {
          data[byteLen - 1] &= (0xFF << trailingBits) & 0xFF;
        }
      }
      const value = { data, bitLength: bitLen };
      const decoded = roundTrip(codec, value);
      expect(decoded.bitLength).toBe(bitLen);
      expect(decoded.data).toEqual(data);
    }
  });
});

// -- Character strings --

describe('PER fuzz: UTF8StringCodec (IA5String) round-trip', () => {
  const IA5_CHARS = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join('');

  it('should round-trip random IA5 strings with size constraints', () => {
    const rng = new Rng(15);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const minSize = rng.int(0, 5);
      const maxSize = minSize + rng.int(1, 30);
      const codec = new UTF8StringCodec({ type: 'IA5String', minSize, maxSize });
      const len = rng.int(minSize, maxSize);
      let str = '';
      for (let j = 0; j < len; j++) {
        str += IA5_CHARS[rng.int(0, IA5_CHARS.length - 1)];
      }
      expect(roundTrip(codec, str)).toBe(str);
    }
  });

  it('should round-trip random VisibleString values', () => {
    const VISIBLE = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join('');
    const rng = new Rng(16);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const minSize = rng.int(0, 3);
      const maxSize = minSize + rng.int(1, 20);
      const codec = new UTF8StringCodec({ type: 'VisibleString', minSize, maxSize });
      const len = rng.int(minSize, maxSize);
      let str = '';
      for (let j = 0; j < len; j++) {
        str += VISIBLE[rng.int(0, VISIBLE.length - 1)];
      }
      expect(roundTrip(codec, str)).toBe(str);
    }
  });

  it('should round-trip UTF8String values', () => {
    const rng = new Rng(17);
    const codec = new UTF8StringCodec({ type: 'UTF8String' });
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const len = rng.int(0, 30);
      let str = '';
      for (let j = 0; j < len; j++) {
        // Mix ASCII and basic multibyte chars
        if (rng.chance(0.7)) {
          str += String.fromCharCode(rng.int(32, 126));
        } else {
          str += String.fromCharCode(rng.int(0xC0, 0xFF)); // Latin-1 supplement
        }
      }
      expect(roundTrip(codec, str)).toBe(str);
    }
  });
});

// -- OID --

describe('PER fuzz: ObjectIdentifierCodec round-trip', () => {
  it('should round-trip random OIDs', () => {
    const rng = new Rng(18);
    const codec = new ObjectIdentifierCodec();
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const arc1 = rng.int(0, 2);
      const arc2 = arc1 < 2 ? rng.int(0, 39) : rng.int(0, 100);
      const numArcs = rng.int(1, 8);
      const arcs = [arc1, arc2];
      for (let j = 0; j < numArcs; j++) {
        arcs.push(rng.int(0, 100000));
      }
      const oid = arcs.join('.');
      expect(roundTrip(codec, oid)).toBe(oid);
    }
  });
});

// -- Null --

describe('PER fuzz: NullCodec round-trip', () => {
  it('should round-trip null', () => {
    const codec = new NullCodec();
    for (let i = 0; i < 10; i++) {
      expect(roundTrip(codec, null)).toBe(null);
    }
  });
});

// -- Sequence --

describe('PER fuzz: SequenceCodec round-trip', () => {
  it('should round-trip sequences with random optional field presence', () => {
    const rng = new Rng(19);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const codec = new SequenceCodec({
        fields: [
          { name: 'id', codec: new IntegerCodec({ min: 0, max: 65535 }) },
          { name: 'name', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 20 }), optional: true },
          { name: 'active', codec: new BooleanCodec(), optional: true },
          { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }), defaultValue: 0 },
        ],
      });

      const id = rng.int(0, 65535);
      const value: Record<string, unknown> = { id };

      if (rng.chance(0.7)) {
        const len = rng.int(1, 20);
        let name = '';
        for (let j = 0; j < len; j++) name += String.fromCharCode(rng.int(65, 90));
        value.name = name;
      }
      if (rng.chance(0.5)) value.active = rng.chance(0.5);
      if (rng.chance(0.6)) value.count = rng.int(0, 255);

      const decoded = roundTrip(codec, value) as Record<string, unknown>;
      expect(decoded.id).toBe(id);
      if (value.name !== undefined) {
        expect(decoded.name).toBe(value.name);
      }
      if (value.active !== undefined) {
        expect(decoded.active).toBe(value.active);
      }
      // DEFAULT field: if not provided, should decode as default
      if (value.count !== undefined) {
        expect(decoded.count).toBe(value.count);
      } else {
        expect(decoded.count).toBe(0);
      }
    }
  });
});

// -- Choice --

describe('PER fuzz: ChoiceCodec round-trip', () => {
  it('should round-trip random choice selections', () => {
    const rng = new Rng(20);
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'integer', codec: new IntegerCodec({ min: 0, max: 1000 }) },
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'text', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 0, maxSize: 50 }) },
      ],
    });

    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const alt = rng.int(0, 2);
      let value: { key: string; value: unknown };
      switch (alt) {
        case 0:
          value = { key: 'integer', value: rng.int(0, 1000) };
          break;
        case 1:
          value = { key: 'flag', value: rng.chance(0.5) };
          break;
        default: {
          const len = rng.int(0, 50);
          let str = '';
          for (let j = 0; j < len; j++) str += String.fromCharCode(rng.int(32, 126));
          value = { key: 'text', value: str };
          break;
        }
      }

      const decoded = roundTrip(codec, value) as { key: string; value: unknown };
      expect(decoded.key).toBe(value.key);
      expect(decoded.value).toEqual(value.value);
    }
  });
});

// -- SequenceOf --

describe('PER fuzz: SequenceOfCodec round-trip', () => {
  it('should round-trip random-length integer arrays', () => {
    const rng = new Rng(21);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const minSize = rng.int(0, 5);
      const maxSize = minSize + rng.int(1, 20);
      const codec = new SequenceOfCodec({
        itemCodec: new IntegerCodec({ min: 0, max: 255 }),
        minSize,
        maxSize,
      });
      const len = rng.int(minSize, maxSize);
      const arr = Array.from({ length: len }, () => rng.int(0, 255));
      const decoded = roundTrip(codec, arr) as number[];
      expect(decoded).toEqual(arr);
    }
  });

  it('should round-trip fixed-size arrays', () => {
    const rng = new Rng(22);
    for (let i = 0; i < 50; i++) {
      const size = rng.int(1, 15);
      const codec = new SequenceOfCodec({
        itemCodec: new BooleanCodec(),
        fixedSize: size,
      });
      const arr = Array.from({ length: size }, () => rng.chance(0.5));
      const decoded = roundTrip(codec, arr) as boolean[];
      expect(decoded).toEqual(arr);
    }
  });
});

// -- SchemaCodec (high-level) --

describe('PER fuzz: SchemaCodec round-trip', () => {
  it('should round-trip via schema-driven codec', () => {
    const rng = new Rng(23);
    const codec = new SchemaCodec({
      type: 'SEQUENCE',
      fields: [
        { name: 'version', schema: { type: 'INTEGER', min: 1, max: 3 } },
        { name: 'flags', schema: { type: 'BIT STRING', fixedSize: 8 } },
        { name: 'payload', schema: { type: 'OCTET STRING', minSize: 0, maxSize: 100 } },
        { name: 'tag', schema: { type: 'ENUMERATED', values: ['a', 'b', 'c'] } },
        { name: 'note', schema: { type: 'IA5String', minSize: 0, maxSize: 50 }, optional: true },
      ],
    });

    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const payloadLen = rng.int(0, 100);
      const payload = new Uint8Array(payloadLen);
      for (let j = 0; j < payloadLen; j++) payload[j] = rng.int(0, 255);

      const flagByte = rng.int(0, 255);

      const value: Record<string, unknown> = {
        version: rng.int(1, 3),
        flags: { data: new Uint8Array([flagByte]), bitLength: 8 },
        payload,
        tag: rng.pick(['a', 'b', 'c']),
      };

      if (rng.chance(0.6)) {
        const len = rng.int(0, 50);
        let note = '';
        for (let j = 0; j < len; j++) note += String.fromCharCode(rng.int(32, 126));
        value.note = note;
      }

      const encoded = codec.encode(value);
      const decoded = codec.decode(encoded) as Record<string, unknown>;

      expect(decoded.version).toBe(value.version);
      expect(decoded.tag).toBe(value.tag);
      expect(decoded.payload).toEqual(value.payload);
      if (value.note !== undefined) {
        expect(decoded.note).toBe(value.note);
      }
    }
  });
});

// -- Multi-codec sequential encoding --

describe('PER fuzz: sequential encoding in shared buffer', () => {
  it('should correctly encode/decode multiple values in a single buffer', () => {
    const rng = new Rng(24);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const buf = BitBuffer.alloc(512);

      const boolVal = rng.chance(0.5);
      const intVal = rng.int(0, 255);
      const enumVal = rng.pick(['x', 'y', 'z']);

      const boolCodec = new BooleanCodec();
      const intCodec = new IntegerCodec({ min: 0, max: 255 });
      const enumCodec = new EnumeratedCodec({ values: ['x', 'y', 'z'] });

      boolCodec.encode(buf, boolVal);
      intCodec.encode(buf, intVal);
      enumCodec.encode(buf, enumVal);

      const readBuf = BitBuffer.from(buf.toUint8Array(), buf.bitLength);
      expect(boolCodec.decode(readBuf)).toBe(boolVal);
      expect(intCodec.decode(readBuf)).toBe(intVal);
      expect(enumCodec.decode(readBuf)).toBe(enumVal);
    }
  });
});
