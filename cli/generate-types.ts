#!/usr/bin/env npx tsx
/**
 * CLI tool to generate TypeScript types and codecs from an ASN.1 file or from
 * a SchemaNode JSON registry.
 *
 * Usage:
 *   npx tsx cli/generate-types.ts <input.asn|input.json> [output.ts] [--import-from <spec>]
 *
 * If no output path is given, prints to stdout.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseAsn1Module } from '../src/parser/AsnParser';
import { convertModuleToSchemaNodes } from '../src/parser/toSchemaNode';
import { generateTypeScript } from '../src/codegen/generateTypeScript';
import type { SchemaRegistry } from '../src/schema/SchemaNode';

const USAGE =
  'Usage: npx tsx cli/generate-types.ts <input.asn|input.json> [output.ts] [--import-from <spec>]';

function main(): void {
  const argv = process.argv.slice(2);

  let importFrom = 'asn1-per-ts';
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--import-from') {
      const value = argv[++i];
      if (!value) {
        console.error('Error: --import-from requires a value');
        process.exit(1);
      }
      importFrom = value;
    } else {
      positional.push(argv[i]);
    }
  }

  if (positional.length < 1) {
    console.error(USAGE);
    process.exit(1);
  }

  const inputPath = path.resolve(positional[0]);
  const outputPath = positional[1] ? path.resolve(positional[1]) : null;

  if (!fs.existsSync(inputPath)) {
    console.error(`Error: input file not found: ${inputPath}`);
    process.exit(1);
  }

  const source = fs.readFileSync(inputPath, 'utf-8');

  let schemas: SchemaRegistry;
  let moduleName: string | undefined;
  if (inputPath.endsWith('.json')) {
    schemas = JSON.parse(source) as SchemaRegistry;
  } else {
    const module = parseAsn1Module(source);
    schemas = convertModuleToSchemaNodes(module);
    moduleName = module.name;
  }

  const code = generateTypeScript(schemas, { importFrom, moduleName });

  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, code, 'utf-8');
    const typeCount = Object.keys(schemas).length;
    console.log(`Wrote ${typeCount} type(s) to ${outputPath}`);
  } else {
    process.stdout.write(code);
  }
}

main();
