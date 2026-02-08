#!/usr/bin/env npx tsx
/**
 * CLI tool to decode a UIC barcode header from a hex fixture,
 * including nested FCB rail ticket data and Intercode 6 extensions.
 *
 * Dynamically discovers schema versions from schemas/uic-barcode/:
 *   - uicBarcodeHeader_v{N}.schema.json  → header format "U{N}"
 *   - uicRailTicketData_v{N}.schema.json → data format "FCB{N}"
 *   - intercode6.schema.json             → Intercode extensions
 *
 * Usage:
 *   npx tsx cli/decode-uic-barcode.ts [path-to-hex-fixture]
 *
 * Defaults to tests/fixtures/uicBarcodeHeader_sample1.hex if no argument given.
 */

import * as fs from 'fs';
import * as path from 'path';
import { SchemaCodec } from '../src/schema/SchemaCodec';
import { SchemaBuilder, type SchemaNode } from '../src/schema/SchemaBuilder';
import { BitBuffer } from '../src/BitBuffer';
import { Codec } from '../src/codecs/Codec';

// ---------------------------------------------------------------------------
// Dynamic schema loading
// ---------------------------------------------------------------------------

const SCHEMAS_DIR = path.join(__dirname, '..', 'schemas', 'uic-barcode');

/** Scan schemas dir and build versioned codec maps. */
function loadSchemas(): {
  headerCodecs: Map<number, SchemaCodec>;
  ticketCodecs: Map<number, Record<string, Codec<unknown>>>;
  intercodeIssuingCodec: SchemaCodec | null;
  intercodeDynamicCodec: SchemaCodec | null;
} {
  const headerCodecs = new Map<number, SchemaCodec>();
  const ticketCodecs = new Map<number, Record<string, Codec<unknown>>>();
  let intercodeIssuingCodec: SchemaCodec | null = null;
  let intercodeDynamicCodec: SchemaCodec | null = null;

  for (const file of fs.readdirSync(SCHEMAS_DIR)) {
    if (!file.endsWith('.schema.json')) continue;
    const filePath = path.join(SCHEMAS_DIR, file);

    // uicBarcodeHeader_v{N}.schema.json
    const headerMatch = file.match(/^uicBarcodeHeader_v(\d+)\.schema\.json$/);
    if (headerMatch) {
      const version = parseInt(headerMatch[1], 10);
      const schemas = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      headerCodecs.set(version, new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode));
      continue;
    }

    // uicRailTicketData_v{N}.schema.json
    const ticketMatch = file.match(/^uicRailTicketData_v(\d+)\.schema\.json$/);
    if (ticketMatch) {
      const version = parseInt(ticketMatch[1], 10);
      const schemas = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      ticketCodecs.set(version, SchemaBuilder.buildAll(schemas as Record<string, SchemaNode>));
      continue;
    }

    // intercode6.schema.json
    if (file === 'intercode6.schema.json') {
      const schemas = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      intercodeIssuingCodec = new SchemaCodec(schemas.IntercodeIssuingData as SchemaNode);
      intercodeDynamicCodec = new SchemaCodec(schemas.IntercodeDynamicData as SchemaNode);
    }
  }

  return { headerCodecs, ticketCodecs, intercodeIssuingCodec, intercodeDynamicCodec };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip whitespace and trailing 'h' suffix from a hex fixture file. */
function loadHexFixture(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf-8');
  return raw.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
}

/** Format a Uint8Array as a hex string. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Pretty-print a value, converting Uint8Arrays to hex. */
function formatValue(value: unknown, indent: number = 0): string {
  const pad = '  '.repeat(indent);
  if (value instanceof Uint8Array) {
    return `${pad}[${value.length} bytes] ${toHex(value)}`;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}(empty array)`;
    return value.map((item, i) => `${pad}[${i}]:\n${formatValue(item, indent + 1)}`).join('\n');
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    return entries
      .map(([k, v]) => {
        if (v instanceof Uint8Array) {
          return `${pad}${k}: [${v.length} bytes] ${toHex(v)}`;
        }
        if (v !== null && typeof v === 'object') {
          return `${pad}${k}:\n${formatValue(v, indent + 1)}`;
        }
        return `${pad}${k}: ${JSON.stringify(v)}`;
      })
      .join('\n');
  }
  return `${pad}${JSON.stringify(value)}`;
}

// ---------------------------------------------------------------------------
// Intercode 6 dispatch helpers
// ---------------------------------------------------------------------------

/** Match extensionId pattern "_<RICS>II1" for IntercodeIssuingData. */
function isIntercodeIssuingExtension(extensionId: string): boolean {
  return /^_\d+II1$/.test(extensionId);
}

/** Match dataFormat pattern "_<RICS>.ID1" for IntercodeDynamicData. */
function isIntercodeDynamicData(dataFormat: string): boolean {
  return /^_\d+\.ID1$/.test(dataFormat);
}

// ---------------------------------------------------------------------------
// Main decode logic
// ---------------------------------------------------------------------------

function main(): void {
  const fixturePath = process.argv[2]
    || path.join(__dirname, '..', 'tests', 'fixtures', 'uicBarcodeHeader_sample1.hex');

  if (!fs.existsSync(fixturePath)) {
    console.error(`Error: file not found: ${fixturePath}`);
    process.exit(1);
  }

  // Load all available schemas
  const { headerCodecs, ticketCodecs, intercodeIssuingCodec, intercodeDynamicCodec } = loadSchemas();

  const headerVersions = [...headerCodecs.keys()].sort((a, b) => a - b);
  const ticketVersions = [...ticketCodecs.keys()].sort((a, b) => a - b);
  console.log(`=== UIC Barcode Decoder ===`);
  console.log(`File: ${fixturePath}`);
  console.log(`Available header schemas: ${headerVersions.map(v => `v${v}`).join(', ')}`);
  console.log(`Available ticket schemas: ${ticketVersions.map(v => `v${v} (FCB${v})`).join(', ')}\n`);

  // Step 1: Try decoding the barcode header with each version until one works.
  // The format field ("U1", "U2", ...) tells us which header version was used.
  // We start by trying with the lowest version (v1) since the format field is
  // at the same position in all versions and we can re-decode with the right one.
  const hex = loadHexFixture(fixturePath);

  // Peek the format field by trying v1 first (always present)
  const peekCodec = headerCodecs.get(headerVersions[0]);
  if (!peekCodec) {
    console.error('Error: no header schemas found');
    process.exit(1);
  }
  const peek = peekCodec.decodeFromHex(hex) as any;
  const format: string = peek.format;

  // Extract version number from format "U1", "U2", etc.
  const headerVersionMatch = format.match(/^U(\d+)$/);
  if (!headerVersionMatch) {
    console.error(`Error: unknown header format "${format}"`);
    process.exit(1);
  }
  const headerVersion = parseInt(headerVersionMatch[1], 10);
  const headerCodec = headerCodecs.get(headerVersion);
  if (!headerCodec) {
    console.error(`Error: no schema for header version ${headerVersion} (format "${format}")`);
    console.error(`Available: ${headerVersions.map(v => `v${v}`).join(', ')}`);
    process.exit(1);
  }

  // Decode with the correct header version
  const header = headerCodec.decodeFromHex(hex) as any;

  console.log(`--- UicBarcodeHeader (${format}) ---`);
  console.log(`format: ${header.format}`);
  console.log(`level2Signature: [${header.level2Signature?.length ?? 0} bytes] ${header.level2Signature ? toHex(header.level2Signature) : 'n/a'}`);

  // Step 2: Level 2 signed data
  const l2 = header.level2SignedData;
  console.log(`\n--- Level2SignedData ---`);
  console.log(`level1Signature: [${l2.level1Signature?.length ?? 0} bytes] ${l2.level1Signature ? toHex(l2.level1Signature) : 'n/a'}`);

  // Step 3: Level 1 data
  const l1 = l2.level1Data;
  console.log(`\n--- Level1Data ---`);
  console.log(`securityProviderNum: ${l1.securityProviderNum ?? 'n/a'}`);
  console.log(`securityProviderIA5: ${l1.securityProviderIA5 ?? 'n/a'}`);
  console.log(`keyId: ${l1.keyId ?? 'n/a'}`);
  console.log(`level1KeyAlg: ${l1.level1KeyAlg ?? 'n/a'}`);
  console.log(`level2KeyAlg: ${l1.level2KeyAlg ?? 'n/a'}`);
  console.log(`level1SigningAlg: ${l1.level1SigningAlg ?? 'n/a'}`);
  console.log(`level2SigningAlg: ${l1.level2SigningAlg ?? 'n/a'}`);
  if (l1.level2PublicKey) {
    console.log(`level2PublicKey: [${l1.level2PublicKey.length} bytes] ${toHex(l1.level2PublicKey)}`);
  }

  // Step 4: Decode each data block in dataSequence
  console.log(`\ndataSequence: ${l1.dataSequence.length} block(s)`);
  for (let i = 0; i < l1.dataSequence.length; i++) {
    const block = l1.dataSequence[i];
    console.log(`\n  --- dataSequence[${i}] ---`);
    console.log(`  dataFormat: ${block.dataFormat}`);
    console.log(`  data: [${block.data.length} bytes] ${toHex(block.data)}`);

    // Dispatch on dataFormat: "FCB{N}" → use ticket schema vN
    const fcbMatch = block.dataFormat.match(/^FCB(\d+)$/);
    if (fcbMatch) {
      const fcbVersion = parseInt(fcbMatch[1], 10);
      const codecs = ticketCodecs.get(fcbVersion);
      if (!codecs) {
        console.error(`  No schema for FCB${fcbVersion}. Available: ${ticketVersions.map(v => `v${v}`).join(', ')}`);
        continue;
      }
      console.log(`\n  >>> Decoding as UicRailTicketData v${fcbVersion} (${block.dataFormat}) <<<`);
      try {
        const buf = BitBuffer.from(block.data);
        const ticket = codecs.UicRailTicketData.decode(buf) as any;
        printRailTicketData(ticket, intercodeIssuingCodec);
      } catch (err) {
        console.error(`  ERROR decoding UicRailTicketData: ${(err as Error).message}`);
      }
    }
  }

  // Step 5: Decode level2Data (dynamic content)
  if (l2.level2Data) {
    console.log(`\n--- Level2Data (dynamic content) ---`);
    console.log(`dataFormat: ${l2.level2Data.dataFormat}`);
    console.log(`data: [${l2.level2Data.data.length} bytes] ${toHex(l2.level2Data.data)}`);

    if (isIntercodeDynamicData(l2.level2Data.dataFormat) && intercodeDynamicCodec) {
      const rics = l2.level2Data.dataFormat.match(/^_(\d+)\.ID1$/)?.[1];
      console.log(`\n>>> Decoding as IntercodeDynamicData (RICS: ${rics}) <<<`);
      try {
        const dynamic = intercodeDynamicCodec.decode(l2.level2Data.data) as any;
        console.log(formatValue(dynamic, 1));
      } catch (err) {
        console.error(`ERROR decoding IntercodeDynamicData: ${(err as Error).message}`);
      }
    }
  }

  console.log(`\n=== Decode complete ===`);
}

/** Print decoded UicRailTicketData with nested extension decoding. */
function printRailTicketData(ticket: any, intercodeIssuingCodec: SchemaCodec | null): void {
  // Issuing detail
  if (ticket.issuingDetail) {
    const iss = ticket.issuingDetail;
    console.log(`\n  --- IssuingDetail ---`);
    if (iss.securityProviderNum != null) console.log(`  securityProviderNum: ${iss.securityProviderNum}`);
    if (iss.securityProviderIA5 != null) console.log(`  securityProviderIA5: ${iss.securityProviderIA5}`);
    if (iss.issuerNum != null) console.log(`  issuerNum: ${iss.issuerNum}`);
    if (iss.issuerIA5 != null) console.log(`  issuerIA5: ${iss.issuerIA5}`);
    console.log(`  issuingYear: ${iss.issuingYear}`);
    console.log(`  issuingDay: ${iss.issuingDay}`);
    if (iss.issuingTime != null) console.log(`  issuingTime: ${iss.issuingTime}`);
    if (iss.issuerName != null) console.log(`  issuerName: ${iss.issuerName}`);
    if (iss.specimen != null) console.log(`  specimen: ${iss.specimen}`);
    if (iss.securePaperTicket != null) console.log(`  securePaperTicket: ${iss.securePaperTicket}`);
    if (iss.activated != null) console.log(`  activated: ${iss.activated}`);
    if (iss.currency != null) console.log(`  currency: ${iss.currency}`);
    if (iss.currencyFract != null) console.log(`  currencyFract: ${iss.currencyFract}`);
    if (iss.issuerPNR != null) console.log(`  issuerPNR: ${iss.issuerPNR}`);

    // Decode extension if present
    if (iss.extension && intercodeIssuingCodec) {
      const ext = iss.extension;
      console.log(`\n  --- IssuingDetail Extension ---`);
      console.log(`  extensionId: ${ext.extensionId}`);
      console.log(`  extensionData: [${ext.extensionData.length} bytes] ${toHex(ext.extensionData)}`);

      if (isIntercodeIssuingExtension(ext.extensionId)) {
        const rics = ext.extensionId.match(/^_(\d+)II1$/)?.[1];
        console.log(`\n  >>> Decoding as IntercodeIssuingData (RICS: ${rics}) <<<`);
        try {
          const issuing = intercodeIssuingCodec.decode(ext.extensionData) as any;
          console.log(`  intercodeVersion: ${issuing.intercodeVersion}`);
          console.log(`  intercodeInstanciation: ${issuing.intercodeInstanciation}`);
          console.log(`  networkId: [${issuing.networkId.length} bytes] ${toHex(issuing.networkId)}`);
          if (issuing.productRetailer) {
            console.log(`  productRetailer:`);
            const pr = issuing.productRetailer;
            if (pr.retailChannel != null) console.log(`    retailChannel: ${pr.retailChannel}`);
            if (pr.retailGeneratorId != null) console.log(`    retailGeneratorId: ${pr.retailGeneratorId}`);
            if (pr.retailServerId != null) console.log(`    retailServerId: ${pr.retailServerId}`);
            if (pr.retailerId != null) console.log(`    retailerId: ${pr.retailerId}`);
            if (pr.retailPointId != null) console.log(`    retailPointId: ${pr.retailPointId}`);
          }
        } catch (err) {
          console.error(`  ERROR decoding IntercodeIssuingData: ${(err as Error).message}`);
        }
      }
    }
  }

  // Traveler detail
  if (ticket.travelerDetail?.traveler) {
    console.log(`\n  --- Travelers ---`);
    for (const t of ticket.travelerDetail.traveler) {
      const parts: string[] = [];
      if (t.firstName) parts.push(`firstName: ${t.firstName}`);
      if (t.lastName) parts.push(`lastName: ${t.lastName}`);
      if (t.dateOfBirth) parts.push(`dateOfBirth: ${t.dateOfBirth}`);
      console.log(`  - ${parts.join(', ')}`);
    }
  }

  // Transport documents
  if (ticket.transportDocument) {
    console.log(`\n  --- Transport Documents (${ticket.transportDocument.length}) ---`);
    for (let i = 0; i < ticket.transportDocument.length; i++) {
      const doc = ticket.transportDocument[i];
      console.log(`\n  [${i}] ticket type: ${Object.keys(doc.ticket || {}).join(', ') || 'unknown'}`);

      const ticketData = doc.ticket;
      if (!ticketData) continue;

      // Get the actual ticket variant (openTicket, pass, reservation, etc.)
      for (const [variant, data] of Object.entries(ticketData)) {
        console.log(`  variant: ${variant}`);
        console.log(formatValue(data, 2));
      }
    }
  }

  // Control detail
  if (ticket.controlDetail) {
    console.log(`\n  --- Control Detail ---`);
    console.log(formatValue(ticket.controlDetail, 2));
  }
}

main();
