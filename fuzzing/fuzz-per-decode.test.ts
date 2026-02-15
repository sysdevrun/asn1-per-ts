/**
 * Fuzz tests for PER unaligned decoding of arbitrary/malformed bytes.
 *
 * Feeds random byte sequences into various codec decoders to verify
 * they either decode successfully or throw clean errors — never crash,
 * produce undefined behavior, or hang.
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
import type { Codec } from '../src/codecs/Codec';
import { Rng } from './generators/asn1-generator';

const FUZZ_ITERATIONS = Number(process.env.FUZZ_ITERATIONS) || 300;

/** Generate random bytes. */
function randomBytes(rng: Rng, maxLen: number): Uint8Array {
  const len = rng.int(0, maxLen);
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = rng.int(0, 255);
  return bytes;
}

/**
 * Attempt to decode random bytes with a codec.
 * Returns true if decoded without error, false if threw.
 * Fails the test if something unexpected happens (non-Error throw, hang).
 */
function tryDecode(codec: Codec<unknown>, bytes: Uint8Array): boolean {
  const buf = BitBuffer.from(bytes);
  try {
    codec.decode(buf);
    return true;
  } catch (e) {
    expect(e).toBeInstanceOf(Error);
    return false;
  }
}

/**
 * Attempt to decode with metadata.
 * Should behave identically to decode() in terms of error handling.
 */
function tryDecodeWithMetadata(codec: Codec<unknown>, bytes: Uint8Array): boolean {
  const buf = BitBuffer.from(bytes);
  try {
    codec.decodeWithMetadata(buf);
    return true;
  } catch (e) {
    expect(e).toBeInstanceOf(Error);
    return false;
  }
}

// -- Primitive codec decode fuzzing --

describe('PER decode fuzz: BooleanCodec', () => {
  it('should decode or reject random bytes', () => {
    const codec = new BooleanCodec();
    const rng = new Rng(100);
    let decoded = 0;
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 10);
      if (tryDecode(codec, bytes)) decoded++;
    }
    // Any non-empty byte array should decode a boolean (1 bit)
    expect(decoded).toBeGreaterThan(0);
  });
});

describe('PER decode fuzz: IntegerCodec', () => {
  const configs = [
    { name: 'constrained 0..255', opts: { min: 0, max: 255 } },
    { name: 'constrained 0..7', opts: { min: 0, max: 7 } },
    { name: 'constrained 0..65535', opts: { min: 0, max: 65535 } },
    { name: 'single value', opts: { min: 42, max: 42 } },
    { name: 'extensible', opts: { min: 0, max: 100, extensible: true } },
    { name: 'semi-constrained', opts: { min: 0 } },
    { name: 'unconstrained', opts: {} },
  ];

  configs.forEach(({ name, opts }, idx) => {
    it(`should decode or reject random bytes (${name})`, () => {
      const codec = new IntegerCodec(opts);
      const rng = new Rng(110 + idx);
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const bytes = randomBytes(rng, 20);
        tryDecode(codec, bytes);
      }
    });
  });
});

describe('PER decode fuzz: EnumeratedCodec', () => {
  it('should decode or reject random bytes (root only)', () => {
    const codec = new EnumeratedCodec({ values: ['a', 'b', 'c', 'd'] });
    const rng = new Rng(120);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 10));
    }
  });

  it('should decode or reject random bytes (with extensions)', () => {
    const codec = new EnumeratedCodec({
      values: ['red', 'green', 'blue'],
      extensionValues: ['yellow', 'purple'],
    });
    const rng = new Rng(121);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 10));
    }
  });
});

describe('PER decode fuzz: OctetStringCodec', () => {
  const configs = [
    { name: 'fixed 4', opts: { fixedSize: 4 } },
    { name: 'fixed 1', opts: { fixedSize: 1 } },
    { name: 'constrained 0..50', opts: { minSize: 0, maxSize: 50 } },
    { name: 'constrained 1..100', opts: { minSize: 1, maxSize: 100 } },
    { name: 'unconstrained', opts: {} },
  ];

  for (const { name, opts } of configs) {
    it(`should decode or reject random bytes (${name})`, () => {
      const codec = new OctetStringCodec(opts);
      const rng = new Rng(130);
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        tryDecode(codec, randomBytes(rng, 60));
      }
    });
  }
});

describe('PER decode fuzz: BitStringCodec', () => {
  it('should decode or reject random bytes (fixed 8)', () => {
    const codec = new BitStringCodec({ fixedSize: 8 });
    const rng = new Rng(140);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 10));
    }
  });

  it('should decode or reject random bytes (constrained 1..32)', () => {
    const codec = new BitStringCodec({ minSize: 1, maxSize: 32 });
    const rng = new Rng(141);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 20));
    }
  });

  it('should decode or reject random bytes (unconstrained)', () => {
    const codec = new BitStringCodec();
    const rng = new Rng(142);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 30));
    }
  });
});

describe('PER decode fuzz: UTF8StringCodec', () => {
  it('should decode or reject random bytes (IA5String)', () => {
    const codec = new UTF8StringCodec({ type: 'IA5String', minSize: 0, maxSize: 50 });
    const rng = new Rng(150);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 50));
    }
  });

  it('should decode or reject random bytes (VisibleString)', () => {
    const codec = new UTF8StringCodec({ type: 'VisibleString', minSize: 0, maxSize: 20 });
    const rng = new Rng(151);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 30));
    }
  });

  it('should decode or reject random bytes (UTF8String)', () => {
    const codec = new UTF8StringCodec({ type: 'UTF8String' });
    const rng = new Rng(152);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 50));
    }
  });
});

describe('PER decode fuzz: ObjectIdentifierCodec', () => {
  it('should decode or reject random bytes', () => {
    const codec = new ObjectIdentifierCodec();
    const rng = new Rng(160);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 30));
    }
  });
});

describe('PER decode fuzz: NullCodec', () => {
  it('should always decode (0 bits)', () => {
    const codec = new NullCodec();
    const rng = new Rng(170);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 5);
      expect(tryDecode(codec, bytes)).toBe(true);
    }
  });
});

// -- Composite codec decode fuzzing --

describe('PER decode fuzz: SequenceCodec', () => {
  it('should decode or reject random bytes (mandatory fields only)', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'a', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'b', codec: new BooleanCodec() },
      ],
    });
    const rng = new Rng(180);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 20));
    }
  });

  it('should decode or reject random bytes (with optional/default fields)', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 65535 }) },
        { name: 'name', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 20 }), optional: true },
        { name: 'active', codec: new BooleanCodec(), defaultValue: true },
      ],
    });
    const rng = new Rng(181);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 30));
    }
  });

  it('should decode or reject random bytes (with extension fields)', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'version', codec: new IntegerCodec({ min: 1, max: 10 }) },
      ],
      extensionFields: [
        { name: 'extra', codec: new BooleanCodec(), optional: true },
      ],
    });
    const rng = new Rng(182);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 20));
    }
  });
});

describe('PER decode fuzz: ChoiceCodec', () => {
  it('should decode or reject random bytes (root alternatives)', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'num', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'text', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 0, maxSize: 10 }) },
      ],
    });
    const rng = new Rng(190);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 20));
    }
  });

  it('should decode or reject random bytes (with extensions)', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'a', codec: new BooleanCodec() },
        { name: 'b', codec: new IntegerCodec({ min: 0, max: 100 }) },
      ],
      extensionAlternatives: [
        { name: 'c', codec: new NullCodec() },
      ],
    });
    const rng = new Rng(191);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 20));
    }
  });
});

describe('PER decode fuzz: SequenceOfCodec', () => {
  it('should decode or reject random bytes (constrained)', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new IntegerCodec({ min: 0, max: 255 }),
      minSize: 0,
      maxSize: 10,
    });
    const rng = new Rng(200);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 30));
    }
  });

  it('should decode or reject random bytes (fixed)', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new BooleanCodec(),
      fixedSize: 5,
    });
    const rng = new Rng(201);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      tryDecode(codec, randomBytes(rng, 10));
    }
  });
});

// -- SchemaCodec decode fuzzing --

describe('PER decode fuzz: SchemaCodec with complex schema', () => {
  const schema = new SchemaCodec({
    type: 'SEQUENCE',
    fields: [
      { name: 'version', schema: { type: 'INTEGER', min: 1, max: 10 } },
      { name: 'flags', schema: { type: 'BIT STRING', fixedSize: 8 } },
      {
        name: 'payload',
        schema: {
          type: 'CHOICE',
          alternatives: [
            { name: 'text', schema: { type: 'IA5String', minSize: 0, maxSize: 100 } },
            { name: 'binary', schema: { type: 'OCTET STRING', minSize: 0, maxSize: 200 } },
            {
              name: 'structured',
              schema: {
                type: 'SEQUENCE',
                fields: [
                  { name: 'kind', schema: { type: 'ENUMERATED', values: ['req', 'res', 'notif'] } },
                  { name: 'data', schema: { type: 'OCTET STRING', minSize: 0, maxSize: 500 }, optional: true },
                ],
              },
            },
          ],
        },
      },
      { name: 'items', schema: { type: 'SEQUENCE OF', item: { type: 'INTEGER', min: 0, max: 255 }, minSize: 0, maxSize: 20 }, optional: true },
    ],
  });

  it('should decode or reject random bytes without crashing', () => {
    const rng = new Rng(210);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 100);
      try {
        schema.decode(bytes);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });
});

// -- decodeWithMetadata fuzzing --

describe('PER decode fuzz: decodeWithMetadata', () => {
  it('should produce valid metadata or throw clean errors', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'x', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'y', codec: new BooleanCodec(), optional: true },
      ],
    });
    const rng = new Rng(220);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 10);
      const ok = tryDecodeWithMetadata(codec, bytes);
      if (ok) {
        // If it decoded, verify basic metadata structure
        const buf = BitBuffer.from(bytes);
        const node = codec.decodeWithMetadata(buf);
        expect(node).toHaveProperty('value');
        expect(node).toHaveProperty('meta');
        expect(typeof node.meta.bitOffset).toBe('number');
        expect(typeof node.meta.bitLength).toBe('number');
      }
    }
  });
});

// -- BitBuffer edge cases --

describe('PER decode fuzz: BitBuffer edge cases', () => {
  it('should handle empty buffer reads', () => {
    const buf = BitBuffer.from(new Uint8Array(0));
    expect(buf.remaining).toBe(0);
    expect(() => buf.readBit()).toThrow();
    expect(() => buf.readBits(1)).toThrow();
  });

  it('should handle reading exact buffer size', () => {
    const rng = new Rng(230);
    for (let i = 0; i < 100; i++) {
      const bytes = randomBytes(rng, 20);
      if (bytes.length === 0) continue;
      const buf = BitBuffer.from(bytes);
      // Read all bits one at a time
      for (let j = 0; j < bytes.length * 8; j++) {
        buf.readBit();
      }
      expect(buf.remaining).toBe(0);
      expect(() => buf.readBit()).toThrow();
    }
  });

  it('should handle readBits with various counts on random data', () => {
    const rng = new Rng(231);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 20);
      if (bytes.length === 0) continue;
      const buf = BitBuffer.from(bytes);
      const bitCount = rng.int(1, Math.min(32, bytes.length * 8));
      const val = buf.readBits(bitCount);
      expect(typeof val).toBe('number');
      expect(val).toBeGreaterThanOrEqual(0);
    }
  });

  it('should handle readOctets on random data', () => {
    const rng = new Rng(232);
    for (let i = 0; i < FUZZ_ITERATIONS; i++) {
      const bytes = randomBytes(rng, 30);
      if (bytes.length === 0) continue;
      const buf = BitBuffer.from(bytes);
      const count = rng.int(0, bytes.length);
      try {
        const octets = buf.readOctets(count);
        expect(octets.length).toBe(count);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });
});

// -- Encode constraint violation fuzzing --

describe('PER fuzz: encoder constraint violations', () => {
  it('should throw on out-of-range integer values', () => {
    const rng = new Rng(240);
    for (let i = 0; i < 100; i++) {
      const min = rng.int(0, 100);
      const max = min + rng.int(1, 100);
      const codec = new IntegerCodec({ min, max });
      const buf = BitBuffer.alloc(32);
      // Value below range
      expect(() => codec.encode(buf, min - 1)).toThrow();
      // Value above range
      expect(() => codec.encode(buf, max + 1)).toThrow();
    }
  });

  it('should throw on unknown enum values', () => {
    const codec = new EnumeratedCodec({ values: ['a', 'b', 'c'] });
    const buf = BitBuffer.alloc(32);
    expect(() => codec.encode(buf, 'unknown')).toThrow();
    expect(() => codec.encode(buf, '')).toThrow();
    expect(() => codec.encode(buf, 'A')).toThrow(); // case sensitive
  });

  it('should throw on unknown choice alternative', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'a', codec: new BooleanCodec() },
        { name: 'b', codec: new IntegerCodec({ min: 0, max: 10 }) },
      ],
    });
    const buf = BitBuffer.alloc(32);
    expect(() => codec.encode(buf, { key: 'x', value: true })).toThrow();
  });
});
