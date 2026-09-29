import { runCli, HELP, type CliIo } from '../../src/cli/cli.js';

/** An in-memory CliIo, so the commands can be exercised without a filesystem. */
function fakeIo(files: Record<string, string> = {}) {
  const written: Record<string, string> = {};
  const stdout: string[] = [];
  const stderr: string[] = [];
  const io: CliIo = {
    readFile(path) {
      const contents = files[path];
      if (contents === undefined) throw new Error(`Input file not found: ${path}`);
      return contents;
    },
    writeFile(path, contents) {
      written[path] = contents;
    },
    out(text) {
      stdout.push(text);
    },
    info(message) {
      stderr.push(message);
    },
    error(message) {
      stderr.push(message);
    },
  };
  return { io, written, out: () => stdout.join(''), err: () => stderr.join('\n') };
}

const ASN = `Demo DEFINITIONS ::= BEGIN
  Ticket ::= SEQUENCE {
    id       INTEGER (0..255),
    version  INTEGER (0..10) DEFAULT 1
  }
END
`;

describe('asn1-per-ts CLI', () => {
  it('prints help and succeeds when help is asked for', () => {
    for (const flag of ['help', '--help', '-h']) {
      const f = fakeIo();
      expect(runCli([flag], f.io)).toBe(0);
      expect(f.out()).toBe(HELP);
    }
  });

  it('prints help and fails when invoked with no command', () => {
    const f = fakeIo();
    expect(runCli([], f.io)).toBe(1);
    expect(f.out()).toBe(HELP);
  });

  it('rejects an unknown command', () => {
    const f = fakeIo();
    expect(runCli(['frobnicate'], f.io)).toBe(1);
    expect(f.err()).toContain("Unknown command: 'frobnicate'");
  });

  describe('types', () => {
    it('writes a TypeScript module to the output path', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['types', 'in.asn', 'out.ts'], f.io)).toBe(0);
      expect(f.written['out.ts']).toContain('export interface Ticket {');
      expect(f.written['out.ts']).toContain('export const codecs');
      expect(f.err()).toContain('Wrote 1 type to out.ts');
    });

    it('writes to stdout when no output path is given', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['types', 'in.asn'], f.io)).toBe(0);
      expect(f.out()).toContain('export interface Ticket {');
      expect(Object.keys(f.written)).toHaveLength(0);
    });

    it('accepts a SchemaNode JSON registry as input', () => {
      const registry = JSON.stringify({
        Flag: { type: 'BOOLEAN' },
      });
      const f = fakeIo({ 'in.json': registry });
      expect(runCli(['types', 'in.json'], f.io)).toBe(0);
      expect(f.out()).toContain('export type Flag = boolean;');
    });

    it('honours --import-from', () => {
      const f = fakeIo({ 'in.asn': ASN });
      runCli(['types', 'in.asn', '--import-from', '../runtime.js'], f.io);
      expect(f.out()).toContain("from '../runtime.js'");
    });

    it('omits the runtime values with --no-runtime', () => {
      const f = fakeIo({ 'in.asn': ASN });
      runCli(['types', 'in.asn', '--no-runtime'], f.io);
      expect(f.out()).toContain('export interface Ticket {');
      expect(f.out()).not.toContain('export const codecs');
      expect(f.out()).not.toContain('createCodecs');
    });

    it('reports a missing value for --import-from', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['types', 'in.asn', '--import-from'], f.io)).toBe(1);
      expect(f.err()).toContain('--import-from requires a value');
    });

    it('reports an unknown option', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['types', 'in.asn', '--wat'], f.io)).toBe(1);
      expect(f.err()).toContain("unknown option '--wat'");
    });

    it('reports a missing input file argument', () => {
      const f = fakeIo();
      expect(runCli(['types'], f.io)).toBe(1);
      expect(f.err()).toContain('missing input file');
    });
  });

  describe('schema', () => {
    it('writes a SchemaNode registry as JSON', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['schema', 'in.asn', 'out.json'], f.io)).toBe(0);
      expect(JSON.parse(f.written['out.json'])).toEqual({
        Ticket: {
          type: 'SEQUENCE',
          fields: [
            { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
            { name: 'version', schema: { type: 'INTEGER', min: 0, max: 10 }, defaultValue: 1 },
          ],
        },
      });
    });

    it('writes to stdout when no output path is given', () => {
      const f = fakeIo({ 'in.asn': ASN });
      expect(runCli(['schema', 'in.asn'], f.io)).toBe(0);
      expect(JSON.parse(f.out())).toHaveProperty('Ticket');
    });
  });

  describe('failures are reported, not thrown', () => {
    it('returns 1 when the input file is missing', () => {
      const f = fakeIo();
      expect(runCli(['types', 'nope.asn'], f.io)).toBe(1);
      expect(f.err()).toContain('Input file not found: nope.asn');
    });

    it('returns 1 when the ASN.1 does not parse', () => {
      const f = fakeIo({ 'bad.asn': 'this is not ASN.1' });
      expect(runCli(['types', 'bad.asn'], f.io)).toBe(1);
      expect(f.err().length).toBeGreaterThan(0);
    });

    it('returns 1 when the JSON does not parse', () => {
      const f = fakeIo({ 'bad.json': '{ oops' });
      expect(runCli(['schema', 'bad.json'], f.io)).toBe(1);
    });
  });
});
