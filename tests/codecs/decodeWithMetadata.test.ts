import { BitBuffer } from '../../src/BitBuffer';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';
import { EnumeratedCodec } from '../../src/codecs/EnumeratedCodec';
import { BitStringCodec } from '../../src/codecs/BitStringCodec';
import { OctetStringCodec } from '../../src/codecs/OctetStringCodec';
import { UTF8StringCodec } from '../../src/codecs/UTF8StringCodec';
import { ObjectIdentifierCodec } from '../../src/codecs/ObjectIdentifierCodec';
import { NullCodec } from '../../src/codecs/NullCodec';
import { SequenceCodec } from '../../src/codecs/SequenceCodec';
import { SequenceOfCodec } from '../../src/codecs/SequenceOfCodec';
import { ChoiceCodec } from '../../src/codecs/ChoiceCodec';
import { stripMetadata } from '../../src/codecs/stripMetadata';
import type { DecodedNode } from '../../src/codecs/DecodedNode';

function encodeToBuffer(codec: { encode(buf: BitBuffer, v: unknown): void }, value: unknown): BitBuffer {
  const buf = BitBuffer.alloc();
  codec.encode(buf, value);
  buf.reset();
  return buf;
}

describe('Primitive codecs decodeWithMetadata', () => {
  describe('BooleanCodec', () => {
    const codec = new BooleanCodec();

    test('decodes true with correct metadata', () => {
      const buf = encodeToBuffer(codec, true);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(true);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(1);
      expect(node.meta.codec).toBe(codec);
      expect(node.meta.rawBytes).toEqual(new Uint8Array([0x80]));
    });

    test('decodes false with correct metadata', () => {
      const buf = encodeToBuffer(codec, false);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(false);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(1);
      expect(node.meta.rawBytes).toEqual(new Uint8Array([0x00]));
    });
  });

  describe('IntegerCodec', () => {
    test('constrained integer metadata', () => {
      const codec = new IntegerCodec({ min: 0, max: 255 });
      const buf = encodeToBuffer(codec, 42);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(42);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(8);
      expect(node.meta.codec).toBe(codec);
      expect(node.meta.rawBytes.length).toBe(1);
    });

    test('unconstrained integer metadata', () => {
      const codec = new IntegerCodec();
      const buf = encodeToBuffer(codec, 100);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(100);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBeGreaterThan(0);
      expect(node.meta.codec).toBe(codec);
    });

    test('extensible integer in-range metadata', () => {
      const codec = new IntegerCodec({ min: 0, max: 100, extensible: true });
      const buf = encodeToBuffer(codec, 50);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(50);
      expect(node.meta.bitOffset).toBe(0);
    });
  });

  describe('EnumeratedCodec', () => {
    const codec = new EnumeratedCodec({ values: ['red', 'green', 'blue'] });

    test('decodes enum with metadata', () => {
      const buf = encodeToBuffer(codec, 'green');
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe('green');
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBeGreaterThan(0);
      expect(node.meta.codec).toBe(codec);
    });
  });

  describe('NullCodec', () => {
    const codec = new NullCodec();

    test('decodes null with zero-length metadata', () => {
      const buf = BitBuffer.from(new Uint8Array([0x00]));
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe(null);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(0);
      expect(node.meta.rawBytes).toEqual(new Uint8Array(0));
      expect(node.meta.codec).toBe(codec);
    });
  });

  describe('OctetStringCodec', () => {
    test('fixed-size octet string metadata', () => {
      const codec = new OctetStringCodec({ fixedSize: 3 });
      const value = new Uint8Array([1, 2, 3]);
      const buf = encodeToBuffer(codec, value);
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toEqual(value);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(24);
      expect(node.meta.codec).toBe(codec);
    });
  });

  describe('BitStringCodec', () => {
    test('fixed-size bit string metadata', () => {
      const codec = new BitStringCodec({ fixedSize: 8 });
      const value = { data: new Uint8Array([0xff]), bitLength: 8 };
      const buf = encodeToBuffer(codec, value);
      const node = codec.decodeWithMetadata(buf);

      expect((node.value as { bitLength: number }).bitLength).toBe(8);
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBe(8);
      expect(node.meta.codec).toBe(codec);
    });
  });

  describe('UTF8StringCodec', () => {
    test('IA5String with size constraints metadata', () => {
      const codec = new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 });
      const buf = encodeToBuffer(codec, 'hello');
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe('hello');
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBeGreaterThan(0);
      expect(node.meta.codec).toBe(codec);
    });
  });

  describe('ObjectIdentifierCodec', () => {
    test('OID metadata', () => {
      const codec = new ObjectIdentifierCodec();
      const buf = encodeToBuffer(codec, '1.2.840');
      const node = codec.decodeWithMetadata(buf);

      expect(node.value).toBe('1.2.840');
      expect(node.meta.bitOffset).toBe(0);
      expect(node.meta.bitLength).toBeGreaterThan(0);
      expect(node.meta.codec).toBe(codec);
    });
  });
});

describe('SequenceCodec decodeWithMetadata', () => {
  test('simple sequence with metadata', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const boolCodec = new BooleanCodec();
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'active', codec: boolCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 42, active: true });
    const node = codec.decodeWithMetadata(buf);

    expect(node.meta.codec).toBe(codec);
    expect(node.meta.bitOffset).toBe(0);

    const fields = node.value as Record<string, DecodedNode>;
    expect(fields.id.value).toBe(42);
    expect(fields.id.meta.codec).toBe(intCodec);
    expect(fields.id.meta.present).toBe(true);
    expect(fields.id.meta.bitLength).toBe(8);

    expect(fields.active.value).toBe(true);
    expect(fields.active.meta.codec).toBe(boolCodec);
    expect(fields.active.meta.present).toBe(true);
    expect(fields.active.meta.bitLength).toBe(1);
  });

  test('sequence with optional present field', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const strCodec = new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 });
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'name', codec: strCodec, optional: true },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 5, name: 'hello' });
    const node = codec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    expect(fields.name.value).toBe('hello');
    expect(fields.name.meta.optional).toBe(true);
    expect(fields.name.meta.present).toBe(true);
    expect(fields.name.meta.bitLength).toBeGreaterThan(0);
  });

  test('sequence with optional absent field', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const strCodec = new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 });
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'name', codec: strCodec, optional: true },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 5 });
    const node = codec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    expect(fields.name.value).toBe(undefined);
    expect(fields.name.meta.optional).toBe(true);
    expect(fields.name.meta.present).toBe(false);
    expect(fields.name.meta.bitLength).toBe(0);
    expect(fields.name.meta.rawBytes).toEqual(new Uint8Array(0));
  });

  test('sequence with default value used', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'version', codec: intCodec, defaultValue: 1 },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 5 });
    const node = codec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    expect(fields.version.value).toBe(1);
    expect(fields.version.meta.isDefault).toBe(true);
    expect(fields.version.meta.present).toBe(false);
    expect(fields.version.meta.bitLength).toBe(0);
  });

  test('sequence with extension fields', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const strCodec = new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 });
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
      ],
      extensionFields: [
        { name: 'name', codec: strCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 42, name: 'world' });
    const node = codec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    expect(fields.id.value).toBe(42);
    expect(fields.name.value).toBe('world');
    expect(fields.name.meta.isExtension).toBe(true);
    expect(fields.name.meta.present).toBe(true);
  });
});

describe('SequenceOfCodec decodeWithMetadata', () => {
  test('sequence of integers', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new SequenceOfCodec({
      itemCodec: intCodec,
      minSize: 0,
      maxSize: 10,
    });

    const values = [10, 20, 30];
    const buf = encodeToBuffer(codec, values);
    const node = codec.decodeWithMetadata(buf);

    expect(node.meta.codec).toBe(codec);
    const items = node.value as DecodedNode[];
    expect(items.length).toBe(3);
    expect(items[0].value).toBe(10);
    expect(items[1].value).toBe(20);
    expect(items[2].value).toBe(30);
    for (const item of items) {
      expect(item.meta.codec).toBe(intCodec);
      expect(item.meta.bitLength).toBe(8);
    }
  });

  test('empty sequence of', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new SequenceOfCodec({
      itemCodec: intCodec,
      minSize: 0,
      maxSize: 10,
    });

    const buf = encodeToBuffer(codec, []);
    const node = codec.decodeWithMetadata(buf);
    const items = node.value as DecodedNode[];
    expect(items.length).toBe(0);
  });

  test('fixed-size sequence of', () => {
    const boolCodec = new BooleanCodec();
    const codec = new SequenceOfCodec({
      itemCodec: boolCodec,
      fixedSize: 3,
    });

    const buf = encodeToBuffer(codec, [true, false, true]);
    const node = codec.decodeWithMetadata(buf);
    const items = node.value as DecodedNode[];
    expect(items.length).toBe(3);
    expect(items[0].value).toBe(true);
    expect(items[1].value).toBe(false);
    expect(items[2].value).toBe(true);
  });
});

describe('ChoiceCodec decodeWithMetadata', () => {
  test('root alternative', () => {
    const boolCodec = new BooleanCodec();
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: boolCodec },
        { name: 'count', codec: intCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { key: 'count', value: 42 });
    const node = codec.decodeWithMetadata(buf);

    expect(node.meta.codec).toBe(codec);
    const choice = node.value as { key: string; value: DecodedNode };
    expect(choice.key).toBe('count');
    expect(choice.value.value).toBe(42);
    expect(choice.value.meta.codec).toBe(intCodec);
  });

  test('extensible choice root alternative', () => {
    const boolCodec = new BooleanCodec();
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: boolCodec },
      ],
      extensionAlternatives: [
        { name: 'count', codec: intCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { key: 'flag', value: true });
    const node = codec.decodeWithMetadata(buf);
    const choice = node.value as { key: string; value: DecodedNode };
    expect(choice.key).toBe('flag');
    expect(choice.value.value).toBe(true);
  });

  test('extensible choice extension alternative', () => {
    const boolCodec = new BooleanCodec();
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: boolCodec },
      ],
      extensionAlternatives: [
        { name: 'count', codec: intCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { key: 'count', value: 42 });
    const node = codec.decodeWithMetadata(buf);
    const choice = node.value as { key: string; value: DecodedNode };
    expect(choice.key).toBe('count');
    expect(choice.value.value).toBe(42);
  });
});

describe('stripMetadata', () => {
  test('strips primitive boolean', () => {
    const codec = new BooleanCodec();
    const buf = encodeToBuffer(codec, true);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toBe(true);
  });

  test('strips primitive integer', () => {
    const codec = new IntegerCodec({ min: 0, max: 255 });
    const buf = encodeToBuffer(codec, 42);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toBe(42);
  });

  test('strips enumerated', () => {
    const codec = new EnumeratedCodec({ values: ['a', 'b', 'c'] });
    const buf = encodeToBuffer(codec, 'b');
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toBe('b');
  });

  test('strips null', () => {
    const codec = new NullCodec();
    const buf = BitBuffer.from(new Uint8Array([0]));
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toBe(null);
  });

  test('strips sequence', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'active', codec: new BooleanCodec() },
      ],
    });

    const original = { id: 42, active: true };
    const buf = encodeToBuffer(codec, original);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toEqual(original);
  });

  test('strips sequence with optional absent field', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'name', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 }), optional: true },
      ],
    });

    const original = { id: 5 };
    const buf = encodeToBuffer(codec, original);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toEqual(original);
  });

  test('strips sequence with default value', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'version', codec: new IntegerCodec({ min: 0, max: 10 }), defaultValue: 1 },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 5 });
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toEqual({ id: 5, version: 1 });
  });

  test('strips sequence of', () => {
    const codec = new SequenceOfCodec({
      itemCodec: new IntegerCodec({ min: 0, max: 255 }),
      minSize: 0,
      maxSize: 10,
    });

    const original = [10, 20, 30];
    const buf = encodeToBuffer(codec, original);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toEqual(original);
  });

  test('strips choice', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
      ],
    });

    const original = { key: 'count', value: 42 };
    const buf = encodeToBuffer(codec, original);
    const node = codec.decodeWithMetadata(buf);
    expect(stripMetadata(node)).toEqual(original);
  });

  test('throws on unknown codec type', () => {
    const fakeNode: DecodedNode = {
      value: 'test',
      meta: {
        bitOffset: 0,
        bitLength: 0,
        rawBytes: new Uint8Array(0),
        codec: { encode: () => {}, decode: () => 'x', decodeWithMetadata: () => ({} as DecodedNode) },
      },
    };
    expect(() => stripMetadata(fakeNode)).toThrow('stripMetadata: unhandled codec type');
  });
});

describe('Invariant: stripMetadata(decodeWithMetadata(x)) === decode(x)', () => {
  test('boolean roundtrip', () => {
    const codec = new BooleanCodec();
    for (const val of [true, false]) {
      const buf1 = encodeToBuffer(codec, val);
      const buf2 = encodeToBuffer(codec, val);
      const decoded = codec.decode(buf1);
      const stripped = stripMetadata(codec.decodeWithMetadata(buf2));
      expect(stripped).toEqual(decoded);
    }
  });

  test('integer roundtrip', () => {
    const codec = new IntegerCodec({ min: 0, max: 1000 });
    for (const val of [0, 42, 500, 1000]) {
      const buf1 = encodeToBuffer(codec, val);
      const buf2 = encodeToBuffer(codec, val);
      const decoded = codec.decode(buf1);
      const stripped = stripMetadata(codec.decodeWithMetadata(buf2));
      expect(stripped).toEqual(decoded);
    }
  });

  test('complex sequence roundtrip', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'active', codec: new BooleanCodec() },
        { name: 'status', codec: new EnumeratedCodec({ values: ['pending', 'approved', 'rejected'] }) },
        { name: 'nickname', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 }), optional: true },
        { name: 'version', codec: new IntegerCodec({ min: 0, max: 10 }), defaultValue: 1 },
      ],
    });

    const testCases = [
      { id: 42, active: true, status: 'approved', nickname: 'test', version: 3 },
      { id: 0, active: false, status: 'pending' },
      { id: 100, active: true, status: 'rejected', nickname: 'user' },
    ];

    for (const val of testCases) {
      const buf1 = encodeToBuffer(codec, val);
      const buf2 = encodeToBuffer(codec, val);
      const decoded = codec.decode(buf1);
      const stripped = stripMetadata(codec.decodeWithMetadata(buf2));
      expect(stripped).toEqual(decoded);
    }
  });

  test('nested sequence/sequenceOf/choice roundtrip', () => {
    const itemCodec = new SequenceCodec({
      fields: [
        { name: 'x', codec: new IntegerCodec({ min: 0, max: 100 }) },
        { name: 'label', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 20 }) },
      ],
    });

    const codec = new SequenceCodec({
      fields: [
        { name: 'items', codec: new SequenceOfCodec({ itemCodec, minSize: 0, maxSize: 5 }) },
        { name: 'choice', codec: new ChoiceCodec({
          alternatives: [
            { name: 'flag', codec: new BooleanCodec() },
            { name: 'num', codec: new IntegerCodec({ min: 0, max: 255 }) },
          ],
        })},
      ],
    });

    const val = {
      items: [
        { x: 10, label: 'first' },
        { x: 20, label: 'second' },
      ],
      choice: { key: 'num', value: 42 },
    };

    const buf1 = encodeToBuffer(codec, val);
    const buf2 = encodeToBuffer(codec, val);
    const decoded = codec.decode(buf1);
    const stripped = stripMetadata(codec.decodeWithMetadata(buf2));
    expect(stripped).toEqual(decoded);
  });

  test('extension fields roundtrip', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: new IntegerCodec({ min: 0, max: 255 }) },
      ],
      extensionFields: [
        { name: 'name', codec: new UTF8StringCodec({ type: 'IA5String', minSize: 1, maxSize: 50 }) },
      ],
    });

    for (const val of [{ id: 42 }, { id: 100, name: 'world' }]) {
      const buf1 = encodeToBuffer(codec, val);
      const buf2 = encodeToBuffer(codec, val);
      const decoded = codec.decode(buf1);
      const stripped = stripMetadata(codec.decodeWithMetadata(buf2));
      expect(stripped).toEqual(decoded);
    }
  });
});

describe('rawBytes correctness', () => {
  test('rawBytes for primitive matches standalone encoding', () => {
    const codec = new IntegerCodec({ min: 0, max: 255 });
    const value = 42;

    // Standalone encoding
    const standalone = BitBuffer.alloc();
    codec.encode(standalone, value);
    const standaloneBytes = standalone.toUint8Array();

    // Extract rawBytes from metadata
    const buf = BitBuffer.alloc();
    codec.encode(buf, value);
    buf.reset();
    const node = codec.decodeWithMetadata(buf);

    expect(node.meta.rawBytes).toEqual(standaloneBytes);
  });

  test('rawBytes for sequence field matches standalone field encoding', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const boolCodec = new BooleanCodec();

    const seqCodec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'active', codec: boolCodec },
      ],
    });

    const buf = encodeToBuffer(seqCodec, { id: 42, active: true });
    const node = seqCodec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    // Check that the field rawBytes match standalone encoding
    const intStandalone = BitBuffer.alloc();
    intCodec.encode(intStandalone, 42);
    expect(fields.id.meta.rawBytes).toEqual(intStandalone.toUint8Array());

    const boolStandalone = BitBuffer.alloc();
    boolCodec.encode(boolStandalone, true);
    expect(fields.active.meta.rawBytes).toEqual(boolStandalone.toUint8Array());
  });

  test('bitOffset values are contiguous in a sequence', () => {
    const intCodec = new IntegerCodec({ min: 0, max: 255 });
    const boolCodec = new BooleanCodec();

    const codec = new SequenceCodec({
      fields: [
        { name: 'id', codec: intCodec },
        { name: 'active', codec: boolCodec },
      ],
    });

    const buf = encodeToBuffer(codec, { id: 42, active: true });
    const node = codec.decodeWithMetadata(buf);
    const fields = node.value as Record<string, DecodedNode>;

    // id starts at 0, uses 8 bits
    expect(fields.id.meta.bitOffset).toBe(0);
    expect(fields.id.meta.bitLength).toBe(8);
    // active starts right after id
    expect(fields.active.meta.bitOffset).toBe(8);
    expect(fields.active.meta.bitLength).toBe(1);
  });
});
