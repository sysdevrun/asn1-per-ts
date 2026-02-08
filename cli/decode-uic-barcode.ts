#!/usr/bin/env npx tsx
/**
 * CLI tool to decode a UIC barcode header (v1) from a hex fixture,
 * including nested FCB2 rail ticket data and Intercode 6 extensions.
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

// Load pre-compiled schemas
import headerSchemas from '../schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';
import railTicketV2Schemas from '../schemas/uic-barcode/uicRailTicketData_v2.schema.json';
import railTicketV3Schemas from '../schemas/uic-barcode/uicRailTicketData.schema.json';
import intercodeSchemas from '../schemas/uic-barcode/intercode6.schema.json';

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
// Build codecs
// ---------------------------------------------------------------------------

const headerCodec = new SchemaCodec(
  headerSchemas.UicBarcodeHeader as unknown as SchemaNode,
);

// UicRailTicketData schemas use $ref nodes, so we must use buildAll()
const railTicketV2Codecs = SchemaBuilder.buildAll(
  railTicketV2Schemas as unknown as Record<string, SchemaNode>,
);
const railTicketV3Codecs = SchemaBuilder.buildAll(
  railTicketV3Schemas as unknown as Record<string, SchemaNode>,
);

const intercodeIssuingCodec = new SchemaCodec(
  (intercodeSchemas as Record<string, unknown>).IntercodeIssuingData as unknown as SchemaNode,
);

const intercodeDynamicCodec = new SchemaCodec(
  (intercodeSchemas as Record<string, unknown>).IntercodeDynamicData as unknown as SchemaNode,
);

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

  console.log(`=== UIC Barcode Decoder ===`);
  console.log(`File: ${fixturePath}\n`);

  // Step 1: Decode UicBarcodeHeader (v1)
  const hex = loadHexFixture(fixturePath);
  const header = headerCodec.decodeFromHex(hex) as any;

  console.log(`--- UicBarcodeHeader ---`);
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

    // Dispatch on dataFormat for FCB decoding
    if (/^FCB[123]$/.test(block.dataFormat)) {
      // FCB1/FCB2 use v2 schema, FCB3 uses v3 schema
      const codecs = block.dataFormat === 'FCB3' ? railTicketV3Codecs : railTicketV2Codecs;
      console.log(`\n  >>> Decoding as UicRailTicketData (${block.dataFormat}) <<<`);
      try {
        const buf = BitBuffer.from(block.data);
        const ticket = codecs.UicRailTicketData.decode(buf) as any;
        printRailTicketData(ticket);
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

    if (isIntercodeDynamicData(l2.level2Data.dataFormat)) {
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
function printRailTicketData(ticket: any): void {
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
    if (iss.extension) {
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
