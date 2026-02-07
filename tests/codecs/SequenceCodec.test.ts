import { BitBuffer } from '../../src/BitBuffer';
import { SequenceCodec } from '../../src/codecs/SequenceCodec';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';
import { NullCodec } from '../../src/codecs/NullCodec';

describe('SequenceCodec', () => {
  describe('all mandatory fields', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
      ],
    });

    it('has no preamble bits', () => {
      expect(codec.preambleBitCount).toBe(0);
    });

    it('encodes/decodes correctly', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { flag: true, count: 42 });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.flag).toBe(true);
      expect(result.count).toBe(42);
    });

    it('throws for missing mandatory field', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, { flag: true })).toThrow('Missing mandatory field');
    });
  });

  describe('optional fields', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'name', codec: new IntegerCodec({ min: 0, max: 7 }) },
        { name: 'age', codec: new IntegerCodec({ min: 0, max: 255 }), optional: true },
        { name: 'flag', codec: new BooleanCodec() },
      ],
    });

    it('has 1 preamble bit', () => {
      expect(codec.preambleBitCount).toBe(1);
    });

    it('encodes with optional field present', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { name: 3, age: 25, flag: true });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.name).toBe(3);
      expect(result.age).toBe(25);
      expect(result.flag).toBe(true);
    });

    it('encodes with optional field absent', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { name: 5, flag: false });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.name).toBe(5);
      expect(result.age).toBeUndefined();
      expect(result.flag).toBe(false);
    });
  });

  describe('default values', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'x', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'y', codec: new IntegerCodec({ min: 0, max: 255 }), defaultValue: 100 },
      ],
    });

    it('has 1 preamble bit', () => {
      expect(codec.preambleBitCount).toBe(1);
    });

    it('uses default value when field equals default', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { x: 10, y: 100 });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.x).toBe(10);
      expect(result.y).toBe(100); // default applied
    });

    it('encodes non-default value', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { x: 10, y: 50 });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.x).toBe(10);
      expect(result.y).toBe(50);
    });

    it('uses default when field missing', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { x: 10 });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.x).toBe(10);
      expect(result.y).toBe(100);
    });
  });

  describe('extensible', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'x', codec: new IntegerCodec({ min: 0, max: 7 }) },
      ],
      extensionFields: [
        { name: 'ext1', codec: new BooleanCodec() },
      ],
    });

    it('is extensible', () => {
      expect(codec.extensible).toBe(true);
    });

    it('encodes without extensions', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { x: 3 });
      buf.reset();
      expect(buf.readBit()).toBe(0); // no extensions
      buf.reset();
      const result = codec.decode(buf);
      expect(result.x).toBe(3);
    });

    it('encodes with extensions', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { x: 5, ext1: true });
      buf.reset();
      expect(buf.readBit()).toBe(1); // has extensions
      buf.reset();
      const result = codec.decode(buf);
      expect(result.x).toBe(5);
      expect(result.ext1).toBe(true);
    });
  });

  describe('multiple optional and default fields', () => {
    const codec = new SequenceCodec({
      fields: [
        { name: 'a', codec: new BooleanCodec() },
        { name: 'b', codec: new IntegerCodec({ min: 0, max: 7 }), optional: true },
        { name: 'c', codec: new IntegerCodec({ min: 0, max: 3 }), defaultValue: 1 },
        { name: 'd', codec: new BooleanCodec(), optional: true },
      ],
    });

    it('has 3 preamble bits', () => {
      expect(codec.preambleBitCount).toBe(3);
    });

    it('round-trips with all fields', () => {
      const buf = BitBuffer.alloc();
      const value = { a: true, b: 5, c: 2, d: false };
      codec.encode(buf, value);
      buf.reset();
      expect(codec.decode(buf)).toEqual(value);
    });

    it('round-trips with only mandatory and defaults', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { a: false });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.a).toBe(false);
      expect(result.b).toBeUndefined();
      expect(result.c).toBe(1); // default
      expect(result.d).toBeUndefined();
    });
  });
});
