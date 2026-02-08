#!/usr/bin/env npx tsx
/**
 * CLI tool to decode a UIC barcode header from a hex fixture,
 * including nested FCB rail ticket data and Intercode 6 extensions.
 *
 * Schema version mapping:
 *   Header format "U1" → uicBarcodeHeader_v1.schema.json
 *   Header format "U2" → uicBarcodeHeader_v2.schema.json
 *   Data format "FCB1" → uicRailTicketData_v1.schema.json
 *   Data format "FCB2" → uicRailTicketData_v2.schema.json
 *   Data format "FCB3" → uicRailTicketData_v3.schema.json
 *   Intercode extensions → intercode6.schema.json
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
// Schema paths and version maps
// ---------------------------------------------------------------------------

const SCHEMAS_DIR = path.join(__dirname, '..', 'schemas', 'uic-barcode');

/** Header format "U{N}" → schema file path */
const HEADER_SCHEMAS: Record<number, string> = {
  1: path.join(SCHEMAS_DIR, 'uicBarcodeHeader_v1.schema.json'),
  2: path.join(SCHEMAS_DIR, 'uicBarcodeHeader_v2.schema.json'),
};

/** Data format "FCB{N}" → schema file path */
const TICKET_SCHEMAS: Record<number, string> = {
  1: path.join(SCHEMAS_DIR, 'uicRailTicketData_v1.schema.json'),
  2: path.join(SCHEMAS_DIR, 'uicRailTicketData_v2.schema.json'),
  3: path.join(SCHEMAS_DIR, 'uicRailTicketData_v3.schema.json'),
};

const INTERCODE_SCHEMA = path.join(SCHEMAS_DIR, 'intercode6.schema.json');

// ---------------------------------------------------------------------------
// Lazy-loaded codec caches
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();
const ticketCodecCache = new Map<number, Record<string, Codec<unknown>>>();
let intercodeIssuingCodec: SchemaCodec | undefined;
let intercodeDynamicCodec: SchemaCodec | undefined;

function getHeaderCodec(version: number): SchemaCodec {
  let codec = headerCodecCache.get(version);
  if (codec) return codec;

  const schemaPath = HEADER_SCHEMAS[version];
  if (!schemaPath) {
    throw new Error(
      `No schema for header v${version}. Supported: ${Object.keys(HEADER_SCHEMAS).map(v => `v${v}`).join(', ')}`,
    );
  }
  const schemas = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
  codec = new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode);
  headerCodecCache.set(version, codec);
  return codec;
}

function getTicketCodecs(version: number): Record<string, Codec<unknown>> {
  let codecs = ticketCodecCache.get(version);
  if (codecs) return codecs;

  const schemaPath = TICKET_SCHEMAS[version];
  if (!schemaPath) {
    throw new Error(
      `No schema for FCB${version}. Supported: ${Object.keys(TICKET_SCHEMAS).map(v => `FCB${v}`).join(', ')}`,
    );
  }
  const schemas = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
  codecs = SchemaBuilder.buildAll(schemas as Record<string, SchemaNode>);
  ticketCodecCache.set(version, codecs);
  return codecs;
}

function getIntercodeIssuingCodec(): SchemaCodec {
  if (intercodeIssuingCodec) return intercodeIssuingCodec;
  const schemas = JSON.parse(fs.readFileSync(INTERCODE_SCHEMA, 'utf-8'));
  intercodeIssuingCodec = new SchemaCodec(schemas.IntercodeIssuingData as SchemaNode);
  intercodeDynamicCodec = new SchemaCodec(schemas.IntercodeDynamicData as SchemaNode);
  return intercodeIssuingCodec;
}

function getIntercodeDynamicCodec(): SchemaCodec {
  if (intercodeDynamicCodec) return intercodeDynamicCodec;
  getIntercodeIssuingCodec(); // loads both
  return intercodeDynamicCodec!;
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

  console.log(`=== UIC Barcode Decoder ===`);
  console.log(`File: ${fixturePath}\n`);

  const hex = loadHexFixture(fixturePath);
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));

  // Step 1: Peek the format field with a minimal decode.
  // UicBarcodeHeader is a non-extensible SEQUENCE with one optional field
  // (level2Signature), producing a 1-bit bitmap before format (IA5String).
  // We read past the bitmap, then decode just the IA5String.
  const peekBuf = BitBuffer.from(bytes);
  peekBuf.readBit(); // skip optional bitmap (level2Signature present/absent)
  const format = SchemaBuilder.build({ type: 'IA5String' } as SchemaNode)
    .decode(peekBuf) as string;

  const headerVersionMatch = format.match(/^U(\d+)$/);
  if (!headerVersionMatch) {
    console.error(`Error: unknown header format "${format}"`);
    process.exit(1);
  }
  const headerVersion = parseInt(headerVersionMatch[1], 10);

  const headerCodec = getHeaderCodec(headerVersion);
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
      console.log(`\n  >>> Decoding as UicRailTicketData v${fcbVersion} (${block.dataFormat}) <<<`);
      try {
        const codecs = getTicketCodecs(fcbVersion);
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
        const dynamic = getIntercodeDynamicCodec().decode(l2.level2Data.data) as any;
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
          const issuing = getIntercodeIssuingCodec().decode(ext.extensionData) as any;
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
