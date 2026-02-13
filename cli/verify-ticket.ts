#!/usr/bin/env npx tsx
/**
 * CLI tool to decode and verify signatures on UIC barcode tickets.
 *
 * Usage:
 *   npx tsx cli/verify-ticket.ts [hex-data-or-file] [--keys path/to/keys.xml]
 *
 * If no argument is given, uses the built-in Soléa fixture.
 * If --keys is provided, attempts Level 1 signature verification using the XML key file.
 *
 * Examples:
 *   npx tsx cli/verify-ticket.ts                              # Soléa fixture
 *   npx tsx cli/verify-ticket.ts solea                        # Soléa fixture
 *   npx tsx cli/verify-ticket.ts cts                          # CTS fixture
 *   npx tsx cli/verify-ticket.ts sncf                         # SNCF TER fixture
 *   npx tsx cli/verify-ticket.ts grand_est                    # Grand Est FCB3 fixture
 *   npx tsx cli/verify-ticket.ts path/to/ticket.hex           # hex file
 *   npx tsx cli/verify-ticket.ts "2355aa..."                  # inline hex
 *   npx tsx cli/verify-ticket.ts solea --keys /tmp/keys.xml   # with level 1 keys
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { decodeTicket } = require('../intercode6-ts/src/decoder') as typeof import('../intercode6-ts/src/decoder');
const { verifyLevel2Signature, verifyLevel1Signature, findKeyInXml } = require('../intercode6-ts/src/verifier') as typeof import('../intercode6-ts/src/verifier');
const { extractSignedData } = require('../intercode6-ts/src/signed-data') as typeof import('../intercode6-ts/src/signed-data');
const {
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} = require('../intercode6-ts/src/fixtures') as typeof import('../intercode6-ts/src/fixtures');

// ---------------------------------------------------------------------------
// Named fixtures
// ---------------------------------------------------------------------------

const FIXTURES: Record<string, string> = {
  sample: SAMPLE_TICKET_HEX,
  sncf: SNCF_TER_TICKET_HEX,
  sncf_ter: SNCF_TER_TICKET_HEX,
  solea: SOLEA_TICKET_HEX,
  cts: CTS_TICKET_HEX,
  grand_est: GRAND_EST_U1_FCB3_HEX,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[\s\n\r]/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function formatDate(year: number, day: number): string {
  const d = new Date(year, 0, day);
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatTime(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`;
}

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function ok(msg: string) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg: string) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function warn(msg: string) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }
function heading(msg: string) { console.log(`\n${BOLD}${CYAN}${msg}${RESET}`); }
function field(label: string, value: unknown) {
  if (value === undefined || value === null) return;
  console.log(`  ${DIM}${label}:${RESET} ${value}`);
}
function bytesField(label: string, bytes: Uint8Array | undefined) {
  if (!bytes) return;
  console.log(`  ${DIM}${label}:${RESET} [${bytes.length} bytes] ${toHex(bytes).substring(0, 60)}${bytes.length > 30 ? '...' : ''}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);

  // Parse --keys option
  let keysXml: string | undefined;
  const keysIdx = args.indexOf('--keys');
  if (keysIdx !== -1) {
    const keysPath = args[keysIdx + 1];
    if (!keysPath) {
      console.error('Error: --keys requires a path to the XML key file');
      process.exit(1);
    }
    keysXml = fs.readFileSync(keysPath, 'utf-8');
    args.splice(keysIdx, 2);
  }

  // Resolve hex input
  let hex: string;
  const input = args[0] || 'solea';

  if (FIXTURES[input.toLowerCase()]) {
    hex = FIXTURES[input.toLowerCase()];
    console.log(`Using ${BOLD}${input.toLowerCase()}${RESET} fixture`);
  } else if (fs.existsSync(input)) {
    hex = fs.readFileSync(input, 'utf-8').trim();
    console.log(`Reading hex from ${BOLD}${input}${RESET}`);
  } else if (/^[0-9a-fA-F\s]+$/.test(input)) {
    hex = input;
    console.log(`Using inline hex (${input.length} chars)`);
  } else {
    console.error(`Unknown input: ${input}`);
    console.error('Use a fixture name (solea, cts, sncf, sample, grand_est), a hex file path, or inline hex.');
    process.exit(1);
  }

  // Decode the ticket
  heading('Decoding ticket...');
  let ticket;
  try {
    ticket = decodeTicket(hex);
    ok('Ticket decoded successfully');
  } catch (e: unknown) {
    fail(`Decoding failed: ${e instanceof Error ? e.message : 'unknown error'}`);
    process.exit(1);
  }

  // Display ticket info
  heading('Ticket Header');
  field('Format', ticket.format);
  field('Header version', ticket.headerVersion);
  bytesField('Level 2 signature', ticket.level2Signature);

  heading('Security');
  field('Security provider', ticket.security.securityProviderNum);
  field('Key ID', ticket.security.keyId);
  field('Level 1 key algorithm', ticket.security.level1KeyAlg);
  field('Level 2 key algorithm', ticket.security.level2KeyAlg);
  field('Level 1 signing algorithm', ticket.security.level1SigningAlg);
  field('Level 2 signing algorithm', ticket.security.level2SigningAlg);
  bytesField('Level 2 public key', ticket.security.level2PublicKey);
  bytesField('Level 1 signature', ticket.security.level1Signature);

  for (const rt of ticket.railTickets) {
    heading(`Rail Ticket (FCB${rt.fcbVersion})`);

    if (rt.issuingDetail) {
      const iss = rt.issuingDetail;
      field('Security provider', iss.securityProviderNum);
      field('Issuer', iss.issuerNum);
      if (iss.issuingYear && iss.issuingDay) {
        field('Issuing date', formatDate(iss.issuingYear, iss.issuingDay));
      }
      field('Issuing year', iss.issuingYear);
      field('Issuing day', iss.issuingDay);
      if (iss.issuingTime != null) field('Issuing time', formatTime(iss.issuingTime));
      field('Issuer name', iss.issuerName);
      field('Specimen', iss.specimen ? 'Yes' : 'No');
      field('Activated', iss.activated ? 'Yes' : 'No');
      field('Currency', iss.currency);
      field('Issuer PNR', iss.issuerPNR);

      if (iss.intercodeIssuing) {
        console.log(`  ${BOLD}Intercode 6 Issuing:${RESET}`);
        field('  Intercode version', iss.intercodeIssuing.intercodeVersion);
        field('  Intercode instanciation', iss.intercodeIssuing.intercodeInstanciation);
        bytesField('  Network ID', iss.intercodeIssuing.networkId);
        if (iss.intercodeIssuing.productRetailer) {
          field('  Retail channel', iss.intercodeIssuing.productRetailer.retailChannel);
        }
      }
    }

    if (rt.travelerDetail?.traveler && rt.travelerDetail.traveler.length > 0) {
      console.log(`  ${BOLD}Travelers:${RESET}`);
      for (const t of rt.travelerDetail.traveler) {
        field('  Name', `${t.firstName ?? ''} ${t.lastName ?? ''}`.trim() || undefined);
        field('  Date of birth', t.dateOfBirth);
      }
    }

    if (rt.transportDocument && rt.transportDocument.length > 0) {
      console.log(`  ${BOLD}Transport Documents (${rt.transportDocument.length}):${RESET}`);
      for (const doc of rt.transportDocument) {
        field('  Type', doc.ticketType);
      }
    }
  }

  if (ticket.dynamicData) {
    heading('Intercode 6 Dynamic Data');
    field('Dynamic content day', ticket.dynamicData.dynamicContentDay);
    if (ticket.dynamicData.dynamicContentTime != null) {
      field('Dynamic content time', ticket.dynamicData.dynamicContentTime);
    }
    field('UTC offset', ticket.dynamicData.dynamicContentUTCOffset);
    field('Duration', ticket.dynamicData.dynamicContentDuration);
  }

  // Signature verification
  heading('Signature Verification');

  const bytes = hexToBytes(hex);

  // Level 2 verification
  const level2Result = await verifyLevel2Signature(bytes);
  if (level2Result.valid) {
    ok(`Level 2 signature: ${GREEN}VALID${RESET} (${level2Result.algorithm})`);
  } else if (level2Result.error?.includes('Missing')) {
    warn(`Level 2 signature: ${YELLOW}NOT PRESENT${RESET} (${level2Result.error})`);
  } else {
    fail(`Level 2 signature: ${RED}INVALID${RESET} (${level2Result.error})`);
  }

  // Level 1 verification
  if (keysXml) {
    const extracted = extractSignedData(bytes);
    const { security } = extracted;
    const issuerCode = security.securityProviderNum;
    const keyId = security.keyId;

    if (issuerCode != null && keyId != null) {
      const pubKey = findKeyInXml(keysXml, issuerCode, keyId);
      if (pubKey) {
        ok(`Found level 1 key for issuer ${issuerCode}, key ID ${keyId} [${pubKey.length} bytes]`);
        const level1Result = await verifyLevel1Signature(bytes, pubKey);
        if (level1Result.valid) {
          ok(`Level 1 signature: ${GREEN}VALID${RESET} (${level1Result.algorithm})`);
        } else {
          fail(`Level 1 signature: ${RED}INVALID${RESET} (${level1Result.error})`);
        }
      } else {
        warn(`No level 1 key found in XML for issuer ${issuerCode}, key ID ${keyId}`);
      }
    } else {
      warn('Cannot look up level 1 key: missing issuer code or key ID');
    }
  } else {
    warn('Level 1 verification skipped (no --keys provided)');
    console.log(`  ${DIM}Use --keys /path/to/uic-publickeys.xml to verify Level 1${RESET}`);
  }

  console.log();
}

main().catch((e) => {
  console.error(`Fatal error: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
