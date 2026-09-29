import { generateTypeScript } from '../codegen/generateTypeScript.js';
import { parseAsn1Module } from '../parser/AsnParser.js';
import { convertModuleToSchemaNodes } from '../parser/toSchemaNode.js';
import type { SchemaRegistry } from '../schema/SchemaNode.js';

/**
 * Everything the CLI touches outside itself, so the commands can be tested
 * without a filesystem. Deliberately free of Node types, to keep them out of
 * the published declarations.
 */
export interface CliIo {
  /** Read a UTF-8 file. Throws if it does not exist. */
  readFile(path: string): string;
  /** Write a UTF-8 file, creating parent directories. */
  writeFile(path: string, contents: string): void;
  /** Write data to stdout verbatim. */
  out(text: string): void;
  /** Write a diagnostic line to stderr. */
  info(message: string): void;
  /** Write an error line to stderr. */
  error(message: string): void;
}

export const HELP = `asn1-per-ts — ASN.1 PER unaligned codec tools

Usage:
  asn1-per-ts types  <input.asn|input.json> [output.ts]   [options]
  asn1-per-ts schema <input.asn>            [output.json]

Commands:
  types    Generate TypeScript types and typed codecs.
  schema   Convert an ASN.1 module to a SchemaNode JSON registry.

Options for 'types':
  --import-from <spec>   Import specifier for the runtime (default: asn1-per-ts)
  --no-runtime           Emit only the types, without 'schemas' and 'codecs'

With no output path the result is written to stdout.
`;

/**
 * Run the CLI.
 *
 * @returns the process exit code.
 */
export function runCli(argv: readonly string[], io: CliIo): number {
  const [command, ...rest] = argv;

  if (command === undefined || command === 'help' || command === '--help' || command === '-h') {
    io.out(HELP);
    return command === undefined ? 1 : 0;
  }

  try {
    switch (command) {
      case 'types':
        return runTypes(rest, io);
      case 'schema':
        return runSchema(rest, io);
      default:
        io.error(`Unknown command: '${command}'`);
        io.error(HELP);
        return 1;
    }
  } catch (error) {
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

function runTypes(argv: readonly string[], io: CliIo): number {
  let importFrom = 'asn1-per-ts';
  let emitRuntime = true;
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--import-from') {
      const value = argv[++i];
      if (value === undefined) {
        io.error('Error: --import-from requires a value');
        return 1;
      }
      importFrom = value;
    } else if (arg === '--no-runtime') {
      emitRuntime = false;
    } else if (arg.startsWith('--')) {
      io.error(`Error: unknown option '${arg}'`);
      return 1;
    } else {
      positional.push(arg);
    }
  }

  const [inputPath, outputPath] = positional;
  if (inputPath === undefined) {
    io.error('Error: missing input file');
    io.error(HELP);
    return 1;
  }

  const { schemas, moduleName } = load(inputPath, io);
  const code = generateTypeScript(schemas, { importFrom, emitRuntime, moduleName });

  return emit(code, outputPath, Object.keys(schemas).length, 'type', io);
}

function runSchema(argv: readonly string[], io: CliIo): number {
  const positional = argv.filter(arg => !arg.startsWith('--'));
  const unknown = argv.find(arg => arg.startsWith('--'));
  if (unknown !== undefined) {
    io.error(`Error: unknown option '${unknown}'`);
    return 1;
  }

  const [inputPath, outputPath] = positional;
  if (inputPath === undefined) {
    io.error('Error: missing input file');
    io.error(HELP);
    return 1;
  }

  const { schemas } = load(inputPath, io);
  const json = `${JSON.stringify(schemas, null, 2)}\n`;

  return emit(json, outputPath, Object.keys(schemas).length, 'type', io);
}

/** Read the input as either an ASN.1 module or a SchemaNode JSON registry. */
function load(
  inputPath: string,
  io: CliIo,
): { schemas: SchemaRegistry; moduleName?: string } {
  const source = io.readFile(inputPath);

  if (inputPath.endsWith('.json')) {
    return { schemas: JSON.parse(source) as SchemaRegistry };
  }
  const module = parseAsn1Module(source);
  return { schemas: convertModuleToSchemaNodes(module), moduleName: module.name };
}

function emit(
  contents: string,
  outputPath: string | undefined,
  count: number,
  noun: string,
  io: CliIo,
): number {
  if (outputPath === undefined) {
    io.out(contents);
    return 0;
  }
  io.writeFile(outputPath, contents);
  io.info(`Wrote ${count} ${noun}${count === 1 ? '' : 's'} to ${outputPath}`);
  return 0;
}
