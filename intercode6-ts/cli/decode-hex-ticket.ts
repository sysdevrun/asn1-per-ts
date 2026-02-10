#!/usr/bin/env npx tsx
/**
 * CLI tool to decode a hex-encoded UIC barcode ticket file.
 *
 * Usage:
 *   npx tsx intercode6-ts/cli/decode-hex-ticket.ts <hex-file>
 *
 * The file should contain the hex-encoded ticket payload (whitespace is ignored,
 * trailing 'h' suffix is stripped). Output is the decoded ticket as JSON.
 */

import * as fs from 'fs';
import { decodeTicket } from '../src';

function toJSON(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return Array.from(value)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return value;
}

function main(): void {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: npx tsx intercode6-ts/cli/decode-hex-ticket.ts <hex-file>');
    process.exit(1);
  }

  if (!fs.existsSync(filePath)) {
    console.error(`Error: file not found: ${filePath}`);
    process.exit(1);
  }

  const hex = fs.readFileSync(filePath, 'utf-8').replace(/\s+/g, '').replace(/h$/i, '');

  const ticket = decodeTicket(hex);
  console.log(JSON.stringify(ticket, toJSON, 2));
}

main();
