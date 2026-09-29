import * as fs from 'fs';
import * as path from 'path';
import { generateTypeScript, parseAsn1Module, convertModuleToSchemaNodes } from '../../src/index.js';
import { codecs, schemas } from '../fixtures/generated/sampleModule.js';
import type {
  Envelope,
  EnvelopeInput,
  IssuingDetail,
  SalesChannel,
  TreeNode,
} from '../fixtures/generated/sampleModule.js';

const ASN_PATH = path.join(__dirname, '..', 'fixtures', 'sample-module.asn');
const GENERATED_PATH = path.join(__dirname, '..', 'fixtures', 'generated', 'sampleModule.ts');

/** Exact type equality, so an assertion cannot pass just because a side is `any`. */
type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2
  ? true
  : false;
type Expect<T extends true> = T;

describe('generated module — checked in and compiled by this test', () => {
  it('is still what the generator produces for the .asn source', () => {
    const module = parseAsn1Module(fs.readFileSync(ASN_PATH, 'utf-8'));
    const regenerated = generateTypeScript(convertModuleToSchemaNodes(module), {
      importFrom: '../../../src/index.js',
      moduleName: module.name,
    });
    expect(regenerated).toBe(fs.readFileSync(GENERATED_PATH, 'utf-8'));
  });

  it('round-trips a value through the generated codecs', () => {
    const value: EnvelopeInput = {
      // version omitted — DEFAULT 1
      detail: { 'issuer-num': 42, channel: 'mobile' }, // issuing-year omitted — DEFAULT 2024
      payload: { key: 'text', value: 'hello' },
      tree: {
        label: 'root',
        flags: { data: new Uint8Array([0b10110000]), bitLength: 8 },
        children: [],
      },
    };

    const decoded: Envelope = codecs.Envelope.decodeFromHex(codecs.Envelope.encodeToHex(value));

    expect(decoded.version).toBe(1);
    expect(decoded.detail['issuing-year']).toBe(2024);
    expect(decoded.detail['issuer-num']).toBe(42);
    expect(decoded.payload).toEqual({ key: 'text', value: 'hello' });
  });

  it('names types instead of inlining them', () => {
    const source = fs.readFileSync(GENERATED_PATH, 'utf-8');
    // The parser inlines type references, so the generator has to match the
    // expanded structures back to the names they came from.
    expect(source).toContain('  detail: IssuingDetail;');
    expect(source).toContain('  payload: Payload;');
    expect(source).toContain('  tree: TreeNode;');
  });

  it('quotes hyphenated ASN.1 field names verbatim', () => {
    const detail: IssuingDetail = {
      'issuer-num': 1,
      'issuing-year': 2024,
      channel: 'online',
    };
    expect(Object.keys(detail)).toContain('issuer-num');
  });

  it('keeps the interchange schemas alongside the types', () => {
    expect(Object.keys(schemas)).toEqual([
      'Sales-Channel',
      'Issuing-Detail',
      'Payload',
      'Tree-Node',
      'Envelope',
    ]);
  });

  it('generates the types the ASN.1 describes', () => {
    type Cases = [
      Expect<Equal<SalesChannel, 'online' | 'counter' | 'mobile' | 'partner'>>,
      // DEFAULT is required after decoding, optional when encoding
      Expect<Equal<Envelope['version'], number>>,
      Expect<Equal<EnvelopeInput['version'], number | undefined>>,
      // OPTIONAL is optional in both directions
      Expect<Equal<IssuingDetail['security-token'], Uint8Array | undefined>>,
      // recursion survives as a named self-reference
      Expect<Equal<TreeNode['children'], TreeNode[] | undefined>>,
    ];
    const cases: Cases = [true, true, true, true, true];
    expect(cases).toHaveLength(5);
  });

  it('rejects values the ASN.1 does not allow', () => {
    // Never called — each @ts-expect-error is the assertion.
    const rejected = () => {
      // @ts-expect-error 'weekly' is not one of the enumeration values
      codecs['Issuing-Detail'].encodeToHex({ 'issuer-num': 1, channel: 'weekly' });
      // @ts-expect-error 'issuer-num' is mandatory
      codecs['Issuing-Detail'].encodeToHex({ channel: 'mobile' });
      // @ts-expect-error 'detail' carries an IssuingDetail, not a string
      codecs.Payload.encodeToHex({ key: 'detail', value: 'nope' });
    };
    expect(typeof rejected).toBe('function');
  });
});
