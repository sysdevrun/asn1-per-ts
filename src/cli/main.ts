#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runCli, type CliIo } from './cli.js';

const io: CliIo = {
  readFile(file) {
    const resolved = path.resolve(file);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Input file not found: ${resolved}`);
    }
    return fs.readFileSync(resolved, 'utf-8');
  },
  writeFile(file, contents) {
    const resolved = path.resolve(file);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, contents, 'utf-8');
  },
  out(text) {
    process.stdout.write(text);
  },
  info(message) {
    process.stderr.write(`${message}\n`);
  },
  error(message) {
    process.stderr.write(`${message}\n`);
  },
};

process.exit(runCli(process.argv.slice(2), io));
