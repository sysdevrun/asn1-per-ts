#!/usr/bin/env npx tsx
/**
 * CLI tool to generate SchemaNode JSON from an ASN.1 file.
 *
 * Usage:
 *   npx tsx cli/generate-schema.ts <input.asn> [output.schema.json]
 *
 * If no output path is given, prints to stdout.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseAsn1Module } from '../src/parser/AsnParser';
import { convertModuleToSchemaNodes } from '../src/parser/toSchemaNode';

function main(): void {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.error('Usage: npx tsx cli/generate-schema.ts <input.asn> [output.schema.json]');
    process.exit(1);
  }

  const inputPath = path.resolve(args[0]);
  const outputPath = args[1] ? path.resolve(args[1]) : null;

  if (!fs.existsSync(inputPath)) {
    console.error(`Error: input file not found: ${inputPath}`);
    process.exit(1);
  }

  const asnText = fs.readFileSync(inputPath, 'utf-8');

  const module = parseAsn1Module(asnText);
  const schemas = convertModuleToSchemaNodes(module);

  const json = JSON.stringify(schemas, null, 2) + '\n';

  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, json, 'utf-8');
    const typeCount = Object.keys(schemas).length;
    console.log(`Wrote ${typeCount} type(s) from module "${module.name}" to ${outputPath}`);
  } else {
    process.stdout.write(json);
  }
}

main();
