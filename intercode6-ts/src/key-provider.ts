/**
 * UIC public key provider for Level 1 signature verification.
 *
 * Fetches public keys from the UIC Rail Public Key registry at
 * https://railpublickey.uic.org/download.php and provides them
 * as a Level1KeyProvider for use with verifySignatures().
 */
import type { Level1KeyProvider } from './types';

/** Default URL for the UIC Rail Public Key registry. */
export const UIC_PUBLIC_KEY_URL = 'https://railpublickey.uic.org/download.php';

/** A parsed entry from the UIC public key XML. */
export interface UicPublicKeyEntry {
  issuerName: string;
  issuerCode: number;
  id: string;
  signatureAlgorithm: string;
  publicKeyBase64: string;
  barcodeVersion?: number;
}

/**
 * Parse the UIC public key XML into structured entries.
 */
export function parseKeysXml(xml: string): UicPublicKeyEntry[] {
  const entries: UicPublicKeyEntry[] = [];
  const keyRegex = /<key>([\s\S]*?)<\/key>/g;
  let match;
  while ((match = keyRegex.exec(xml)) !== null) {
    const block = match[1];
    const issuerCode = parseInt(getTagValue(block, 'issuerCode'), 10);
    if (isNaN(issuerCode)) continue;
    entries.push({
      issuerName: getTagValue(block, 'issuerName'),
      issuerCode,
      id: getTagValue(block, 'id'),
      signatureAlgorithm: getTagValue(block, 'signatureAlgorithm'),
      publicKeyBase64: getTagValue(block, 'publicKey'),
      barcodeVersion: parseInt(getTagValue(block, 'barcodeVersion'), 10) || undefined,
    });
  }
  return entries;
}

function getTagValue(block: string, tag: string): string {
  const regex = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`);
  const match = block.match(regex);
  return match ? match[1].trim() : '';
}

/**
 * Decode a Base64 string to Uint8Array.
 * Works in both Node.js and browser environments.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s/g, '');
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- Minimal ASN.1 DER parser ---

interface DerElement {
  tag: number;
  contents: Uint8Array;
  totalLength: number;
}

function readDerElement(data: Uint8Array, offset: number): DerElement {
  const tag = data[offset];
  let pos = offset + 1;

  let length: number;
  const firstLenByte = data[pos];
  if (firstLenByte < 0x80) {
    length = firstLenByte;
    pos += 1;
  } else {
    const numBytes = firstLenByte & 0x7f;
    pos += 1;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + data[pos + i];
    }
    pos += numBytes;
  }

  const contents = data.subarray(pos, pos + length);
  const totalLength = pos - offset + length;

  return { tag, contents, totalLength };
}

function readDerChildren(data: Uint8Array): DerElement[] {
  const elements: DerElement[] = [];
  let offset = 0;
  while (offset < data.length) {
    const elem = readDerElement(data, offset);
    elements.push(elem);
    offset += elem.totalLength;
  }
  return elements;
}

/**
 * Extract raw public key bytes from an X.509 certificate or SubjectPublicKeyInfo DER.
 *
 * For EC keys, returns the raw EC point (e.g. 04||x||y for uncompressed).
 * For DSA keys, returns the DER-encoded INTEGER y value.
 */
export function extractPublicKeyFromDer(der: Uint8Array): Uint8Array {
  const outer = readDerElement(der, 0);
  if (outer.tag !== 0x30) {
    throw new Error(`Expected SEQUENCE (0x30), got 0x${outer.tag.toString(16)}`);
  }

  const outerChildren = readDerChildren(outer.contents);

  // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE (algId), BIT STRING (key) }
  if (outerChildren.length >= 2 && outerChildren[1].tag === 0x03) {
    return outerChildren[1].contents.subarray(1); // skip unused bits byte
  }

  // X.509 Certificate: navigate to SubjectPublicKeyInfo in TBSCertificate
  const tbs = outerChildren[0];
  if (tbs.tag !== 0x30) {
    throw new Error(`Expected TBSCertificate SEQUENCE, got 0x${tbs.tag.toString(16)}`);
  }

  const tbsChildren = readDerChildren(tbs.contents);

  // TBSCertificate fields:
  // [0] version (OPTIONAL, context tag 0xa0)
  // INTEGER serialNumber
  // SEQUENCE signature
  // SEQUENCE issuer
  // SEQUENCE validity
  // SEQUENCE subject
  // SEQUENCE subjectPublicKeyInfo
  let idx = 0;
  if (tbsChildren[0].tag === 0xa0) {
    idx = 1; // skip explicit [0] version
  }
  // Skip serialNumber(1) + signature(1) + issuer(1) + validity(1) + subject(1) = 5
  idx += 5;

  const spki = tbsChildren[idx];
  if (!spki || spki.tag !== 0x30) {
    throw new Error(
      `Expected SubjectPublicKeyInfo SEQUENCE at index ${idx}, got 0x${spki?.tag.toString(16) ?? 'undefined'}`,
    );
  }

  const spkiChildren = readDerChildren(spki.contents);
  const bitString = spkiChildren[1];
  if (!bitString || bitString.tag !== 0x03) {
    throw new Error(`Expected BIT STRING in SPKI, got 0x${bitString?.tag.toString(16) ?? 'undefined'}`);
  }

  // BIT STRING: first byte = unused bits count (0 for keys), rest = raw key
  return bitString.contents.subarray(1);
}

/**
 * Create a Level1KeyProvider that fetches keys from the UIC Rail Public Key registry.
 *
 * The provider fetches the key registry XML once and caches it.
 *
 * @param options.url - Custom URL for the key registry (defaults to UIC endpoint).
 * @param options.xml - Pre-fetched XML string (skips fetch, useful for testing/offline).
 */
export function createUicKeyProvider(options?: {
  url?: string;
  xml?: string;
}): Level1KeyProvider {
  let cachedEntries: UicPublicKeyEntry[] | null = null;

  async function getEntries(): Promise<UicPublicKeyEntry[]> {
    if (cachedEntries) return cachedEntries;

    let xml: string;
    if (options?.xml) {
      xml = options.xml;
    } else {
      const url = options?.url ?? UIC_PUBLIC_KEY_URL;
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to fetch UIC public keys: ${response.status} ${response.statusText}`);
      }
      xml = await response.text();
    }

    cachedEntries = parseKeysXml(xml);
    return cachedEntries;
  }

  return {
    async getPublicKey(
      securityProvider: { num?: number; ia5?: string },
      keyId: number,
    ): Promise<Uint8Array> {
      const entries = await getEntries();

      const issuerCode = securityProvider.num;
      if (issuerCode === undefined) {
        throw new Error('Security provider number is required for UIC key lookup');
      }

      const matching = entries.filter(
        e => e.issuerCode === issuerCode && parseInt(e.id, 10) === keyId,
      );

      if (matching.length === 0) {
        throw new Error(
          `No public key found for issuerCode=${issuerCode}, keyId=${keyId}`,
        );
      }

      const entry = matching[0];
      const certDer = base64ToBytes(entry.publicKeyBase64);
      return extractPublicKeyFromDer(certDer);
    },
  };
}
