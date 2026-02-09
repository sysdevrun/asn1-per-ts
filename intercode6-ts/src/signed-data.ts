/**
 * Extract signed data bytes from a UIC barcode using decodeWithMetadata.
 *
 * Instead of decoding and re-encoding (which risks round-trip mismatches),
 * this module decodes with metadata and extracts the exact original bytes
 * from the DecodedNode tree via rawBytes.
 */
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  type DecodedNode,
  type SchemaNode,
  stripMetadata,
} from 'per-unaligned-ts';
import { HEADER_SCHEMAS } from './schemas';

// ---------------------------------------------------------------------------
// Codec cache (mirrors decoder.ts cache pattern)
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();

function getHeaderCodec(version: number): SchemaCodec {
  let codec = headerCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) {
    throw new Error(`No schema for header v${version}. Supported: v1, v2`);
  }
  codec = new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode);
  headerCodecCache.set(version, codec);
  return codec;
}

function detectHeaderVersion(bytes: Uint8Array): number {
  const peekBuf = BitBuffer.from(bytes);
  peekBuf.readBit(); // skip optional bitmap
  const format = SchemaBuilder.build({ type: 'IA5String' } as SchemaNode).decode(peekBuf) as string;
  const match = format.match(/^U(\d+)$/);
  if (!match) {
    throw new Error(`Unknown header format "${format}"`);
  }
  return parseInt(match[1], 10);
}

// ---------------------------------------------------------------------------
// Extracted signed data
// ---------------------------------------------------------------------------

/** The raw bytes and decoded fields extracted from a UIC barcode header. */
export interface ExtractedSignedData {
  /** Header version (1 or 2). */
  headerVersion: number;
  /** The exact PER-encoded bytes of level1Data (signed by level1Signature). */
  level1DataBytes: Uint8Array;
  /** The exact PER-encoded bytes of level2SignedData (signed by level2Signature). */
  level2SignedBytes: Uint8Array;
  /** Level 1 signature bytes, if present. */
  level1Signature?: Uint8Array;
  /** Level 2 signature bytes, if present. */
  level2Signature?: Uint8Array;
  /** Security provider number from level1Data. */
  securityProviderNum?: number;
  /** Security provider IA5 string from level1Data. */
  securityProviderIA5?: string;
  /** Key ID from level1Data. */
  keyId?: number;
  /** Level 1 key algorithm OID. */
  level1KeyAlg?: string;
  /** Level 2 key algorithm OID. */
  level2KeyAlg?: string;
  /** Level 1 signing algorithm OID. */
  level1SigningAlg?: string;
  /** Level 2 signing algorithm OID. */
  level2SigningAlg?: string;
  /** Level 2 public key bytes (embedded in level1Data). */
  level2PublicKey?: Uint8Array;
}

/**
 * Extract the signed data bytes and security fields from a UIC barcode.
 *
 * Decodes the header with metadata, then navigates the DecodedNode tree
 * to extract rawBytes for level1Data and level2SignedData. Also extracts
 * decoded security fields via stripMetadata.
 *
 * @param bytes - The raw barcode payload bytes.
 * @returns Extracted signed data and security metadata.
 */
export function extractSignedData(bytes: Uint8Array): ExtractedSignedData {
  const headerVersion = detectHeaderVersion(bytes);
  const headerCodec = getHeaderCodec(headerVersion);
  const root: DecodedNode = headerCodec.decodeWithMetadata(bytes);

  // Navigate the metadata tree
  const headerFields = root.value as Record<string, DecodedNode>;
  const level2SignedDataNode = headerFields.level2SignedData;
  const l2Fields = level2SignedDataNode.value as Record<string, DecodedNode>;
  const level1DataNode = l2Fields.level1Data;

  // Extract the exact original bytes (no re-encoding)
  const level1DataBytes = level1DataNode.meta.rawBytes;
  const level2SignedBytes = level2SignedDataNode.meta.rawBytes;

  // Extract decoded security fields using stripMetadata
  const l1Stripped = stripMetadata(level1DataNode) as Record<string, unknown>;

  // Extract signatures (these are decoded values, not rawBytes)
  const level1SigNode = l2Fields.level1Signature;
  const level1Signature = level1SigNode?.meta.present !== false
    ? stripMetadata(level1SigNode) as Uint8Array | undefined
    : undefined;

  const level2SigNode = headerFields.level2Signature;
  const level2Signature = level2SigNode?.meta.present !== false
    ? stripMetadata(level2SigNode) as Uint8Array | undefined
    : undefined;

  return {
    headerVersion,
    level1DataBytes,
    level2SignedBytes,
    level1Signature: level1Signature ?? undefined,
    level2Signature: level2Signature ?? undefined,
    securityProviderNum: l1Stripped.securityProviderNum as number | undefined,
    securityProviderIA5: l1Stripped.securityProviderIA5 as string | undefined,
    keyId: l1Stripped.keyId as number | undefined,
    level1KeyAlg: l1Stripped.level1KeyAlg as string | undefined,
    level2KeyAlg: l1Stripped.level2KeyAlg as string | undefined,
    level1SigningAlg: l1Stripped.level1SigningAlg as string | undefined,
    level2SigningAlg: l1Stripped.level2SigningAlg as string | undefined,
    level2PublicKey: l1Stripped.level2PublicKey as Uint8Array | undefined,
  };
}
