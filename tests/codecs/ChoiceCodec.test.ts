import { BitBuffer } from '../../src/BitBuffer';
import { ChoiceCodec } from '../../src/codecs/ChoiceCodec';
import { BooleanCodec } from '../../src/codecs/BooleanCodec';
import { IntegerCodec } from '../../src/codecs/IntegerCodec';
import { NullCodec } from '../../src/codecs/NullCodec';

describe('ChoiceCodec', () => {
  describe('non-extensible', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
        { name: 'nothing', codec: new NullCodec() },
      ],
    });

    it('is not extensible', () => {
      expect(codec.extensible).toBe(false);
    });

    it('encodes/decodes first alternative', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'flag', value: true });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('flag');
      expect(result.value).toBe(true);
    });

    it('encodes/decodes second alternative', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'count', value: 42 });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('count');
      expect(result.value).toBe(42);
    });

    it('encodes/decodes third alternative', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'nothing', value: null });
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('nothing');
      expect(result.value).toBeNull();
    });

    it('throws for unknown alternative', () => {
      const buf = BitBuffer.alloc();
      expect(() => codec.encode(buf, { key: 'unknown', value: 0 })).toThrow();
    });
  });

  describe('single alternative', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'only', codec: new BooleanCodec() },
      ],
    });

    it('encodes without index bits', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'only', value: true });
      expect(buf.bitLength).toBe(1); // only the boolean value, no index
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('only');
      expect(result.value).toBe(true);
    });
  });

  describe('extensible', () => {
    const codec = new ChoiceCodec({
      alternatives: [
        { name: 'flag', codec: new BooleanCodec() },
        { name: 'count', codec: new IntegerCodec({ min: 0, max: 255 }) },
      ],
      extensionAlternatives: [
        { name: 'extra', codec: new IntegerCodec({ min: 0, max: 7 }) },
      ],
    });

    it('is extensible', () => {
      expect(codec.extensible).toBe(true);
    });

    it('encodes root alternative', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'flag', value: false });
      buf.reset();
      expect(buf.readBit()).toBe(0); // ext bit = 0
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('flag');
      expect(result.value).toBe(false);
    });

    it('encodes extension alternative', () => {
      const buf = BitBuffer.alloc();
      codec.encode(buf, { key: 'extra', value: 5 });
      buf.reset();
      expect(buf.readBit()).toBe(1); // ext bit = 1
      buf.reset();
      const result = codec.decode(buf);
      expect(result.key).toBe('extra');
      expect(result.value).toBe(5);
    });
  });

  it('throws when constructed with no alternatives', () => {
    expect(() => new ChoiceCodec({ alternatives: [] })).toThrow();
  });
});
