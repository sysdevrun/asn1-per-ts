import peggy from 'peggy';
import { ASN1_GRAMMAR } from './grammar.js';
import type { AsnModule } from './types.js';

let cachedParser: peggy.Parser | null = null;

function getParser(): peggy.Parser {
  if (!cachedParser) {
    cachedParser = peggy.generate(ASN1_GRAMMAR);
  }
  return cachedParser;
}

/**
 * Parse an ASN.1 module definition string into an AST.
 *
 * @param input - ASN.1 module text (e.g. contents of a .asn file)
 * @returns Parsed ASN.1 module AST
 * @throws Error if the input is not valid ASN.1 notation
 */
export function parseAsn1Module(input: string): AsnModule {
  const parser = getParser();
  return parser.parse(input) as AsnModule;
}
