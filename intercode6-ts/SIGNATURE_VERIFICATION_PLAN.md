# Signature Verification Plan for intercode6-ts

## Background

UIC railway barcodes use a two-level digital signature scheme:

```
UicBarcodeHeader
├── format: "U1" | "U2"
├── level2SignedData                    ← signed by level2Signature
│   ├── level1Data                     ← signed by level1Signature
│   │   ├── securityProviderNum/IA5
│   │   ├── keyId
│   │   ├── dataSequence (FCB blocks)
│   │   ├── level1KeyAlg (OID)
│   │   ├── level2KeyAlg (OID)
│   │   ├── level1SigningAlg (OID)
│   │   ├── level2SigningAlg (OID)
│   │   ├── level2PublicKey            ← EC public key for level2 verification
│   │   └── [validity fields in v2]
│   ├── level1Signature (OCTET STRING)
│   └── level2Data (optional)
└── level2Signature (OCTET STRING)
```

- **Level 1 signature** covers `level1Data` (PER-encoded). Verified with an
  externally-fetched public key (looked up by `securityProviderNum` + `keyId`).
- **Level 2 signature** covers `level2SignedData` (PER-encoded, which includes
  `level1Data` + `level1Signature` + `level2Data`). Verified with
  `level2PublicKey` embedded in `level1Data`.

---

## 1. Extracting the Signed Data Bytes

### Problem

To verify a signature we need the exact bytes that were signed. These are the
**canonical PER unaligned encoding** of `level1Data` (for level 1) and
`level2SignedData` (for level 2).

### Approach — `decodeWithMetadata`

The library now supports `decodeWithMetadata()` on every codec (including
`SchemaCodec`). This returns a `DecodedNode` tree where each node carries a
`FieldMeta` with:

- `bitOffset` — start bit position in the source buffer
- `bitLength` — number of bits consumed by the encoding
- `rawBytes` — the exact original bytes extracted from the source buffer
  (left-aligned, trailing bits zero-padded)

Instead of the risky decode-then-re-encode path, we decode the header
**once** with metadata and read the signed bytes directly from the tree:

```typescript
import { SchemaCodec, type DecodedNode } from 'asn1-per-ts';

const headerCodec = getHeaderCodec(headerVersion);
const root: DecodedNode = headerCodec.decodeWithMetadata(bytes);

// Navigate the metadata tree (SEQUENCE fields are Record<string, DecodedNode>)
const headerFields = root.value as Record<string, DecodedNode>;
const level2SignedDataNode = headerFields.level2SignedData;

const l2Fields = level2SignedDataNode.value as Record<string, DecodedNode>;
const level1DataNode = l2Fields.level1Data;

// Extract the exact original bytes — no re-encoding needed
const level1DataBytes = level1DataNode.meta.rawBytes;   // signed by level1Signature
const level2SignedBytes = level2SignedDataNode.meta.rawBytes; // signed by level2Signature
```

---

## 2. OID-to-Algorithm Mapping

### Supported Algorithms

Based on the UIC specification:

| OID | Algorithm | Use |
|-----|-----------|-----|
| `1.2.840.10045.4.3.2` | ECDSA with SHA-256 | Signing |
| `1.2.840.10045.4.3.3` | ECDSA with SHA-384 | Signing |
| `1.2.840.10045.4.3.4` | ECDSA with SHA-512 | Signing |
| `2.16.840.1.101.3.4.3.1` | DSA with SHA-224 | Signing |
| `2.16.840.1.101.3.4.3.2` | DSA with SHA-256 | Signing |
| `1.2.840.10045.3.1.7` | secp256r1 (P-256) | Key algorithm |
| `1.3.132.0.34` | secp384r1 (P-384) | Key algorithm |
| `1.3.132.0.35` | secp521r1 (P-521) | Key algorithm |
| `1.2.840.113549.1.1.1` | RSA | Key algorithm |
| `1.2.840.113549.1.1.11` | RSA with SHA-256 | Signing |

### Implementation

```typescript
// New file: src/oids.ts
const SIGNING_ALGORITHMS: Record<string, { hash: string; type: string }> = {
  '1.2.840.10045.4.3.2': { hash: 'SHA-256', type: 'ECDSA' },
  '1.2.840.10045.4.3.3': { hash: 'SHA-384', type: 'ECDSA' },
  '1.2.840.10045.4.3.4': { hash: 'SHA-512', type: 'ECDSA' },
  '2.16.840.1.101.3.4.3.1': { hash: 'SHA-224', type: 'DSA' },
  '2.16.840.1.101.3.4.3.2': { hash: 'SHA-256', type: 'DSA' },
  '1.2.840.113549.1.1.11': { hash: 'SHA-256', type: 'RSA' },
};

const KEY_ALGORITHMS: Record<string, { curve?: string; type: string }> = {
  '1.2.840.10045.3.1.7': { curve: 'P-256', type: 'EC' },
  '1.3.132.0.34':        { curve: 'P-384', type: 'EC' },
  '1.3.132.0.35':        { curve: 'P-521', type: 'EC' },
  '1.2.840.113549.1.1.1': { type: 'RSA' },
};
```

---

## 3. Signature Format Conversion

### ECDSA Signature Format

UIC barcodes store ECDSA signatures as **raw concatenated (r || s)** values
(e.g., 64 bytes for P-256: 32-byte r + 32-byte s).

Some crypto APIs (e.g. Web Crypto, Node.js `crypto.verify()`) expect
**DER-encoded** signatures. A conversion may be needed depending on the
library:

```
Raw:  r (32 bytes) || s (32 bytes)  → 64 bytes total
DER:  SEQUENCE { INTEGER r, INTEGER s }  → ~70-72 bytes
```

### Implementation

```typescript
// Convert raw (r || s) to DER-encoded ECDSA signature
function rawToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const r = raw.slice(0, half);
  const s = raw.slice(half);

  function encodeInteger(value: Uint8Array): Uint8Array {
    // Strip leading zeros, add 0x00 padding if high bit set
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    const trimmed = value.slice(start);
    const needsPad = trimmed[0] & 0x80;
    const len = trimmed.length + (needsPad ? 1 : 0);
    const buf = new Uint8Array(2 + len);
    buf[0] = 0x02; // INTEGER tag
    buf[1] = len;
    if (needsPad) buf[2] = 0x00;
    buf.set(trimmed, 2 + (needsPad ? 1 : 0));
    return buf;
  }

  const rDer = encodeInteger(r);
  const sDer = encodeInteger(s);
  const seq = new Uint8Array(2 + rDer.length + sDer.length);
  seq[0] = 0x30; // SEQUENCE tag
  seq[1] = rDer.length + sDer.length;
  seq.set(rDer, 2);
  seq.set(sDer, 2 + rDer.length);
  return seq;
}
```

> **Note**: When using `@noble/curves`, DER conversion is typically not
> needed — `@noble/curves` works with raw `(r || s)` signatures directly.
> This conversion is only required when using the Web Crypto API fallback.

### DSA Signature Format

DSA signatures also use (r || s) concatenation in UIC barcodes and need
the same DER conversion.

---

## 4. Public Key Handling

### Level 2 Public Key (embedded in barcode)

The `level2PublicKey` field contains a raw EC public key in one of two forms:

- **Uncompressed** (65 bytes for P-256): `04 || Qx (32) || Qy (32)`
- **Compressed** (33 bytes for P-256): `02|03 || Qx (32)`

Using `@noble/curves`, raw EC points (both compressed and uncompressed)
can be used directly without any DER/SPKI wrapping:

```typescript
import { p256 } from '@noble/curves/p256';

// Verify directly with the raw public key point
const isValid = p256.verify(signature, messageHash, level2PublicKey);
```

This works in both browsers and Node.js with no platform-specific code.

### Level 1 Public Key (external lookup)

The level 1 public key is **not in the barcode**. It must be fetched from a
key management system using:

- `securityProviderNum` (or `securityProviderIA5`) — identifies the issuer
- `keyId` — identifies which key

#### Fetching Level 1 Public Keys from the UIC Registry

The UIC publishes all railway operator public keys at:

```
https://railpublickey.uic.org/download.php
```

This endpoint returns an XML document containing a `<keys>` root element with
multiple `<key>` entries. Each entry has:

| Field | Description |
|-------|-------------|
| `issuerCode` | Numeric issuer code (matches `securityProviderNum` in the barcode) |
| `issuerName` | Human-readable name (e.g. "Deutsche Bahn AG", "SNCF Voyageurs") |
| `id` | Key identifier (matches `keyId` in the barcode) |
| `publicKey` | Base64-encoded public key bytes |
| `signatureAlgorithm` | Algorithm name (e.g. "SHA256withECDSA", "SHA1withDSA") |
| `versionType` | Key variant (e.g. "FCB", "TLB", "DOS", "SSB") |
| `barcodeVersion` | Barcode format version |
| `startDate` / `endDate` | Key validity period |

**To find the correct level 1 public key for a barcode:**

1. Decode the barcode header to extract `securityProviderNum` and `keyId`.
2. Fetch or cache the XML from `https://railpublickey.uic.org/download.php`.
3. Find the `<key>` entry where `<issuerCode>` matches `securityProviderNum`
   and `<id>` matches `keyId`.
4. Base64-decode the `<publicKey>` field to get the raw key bytes.

```typescript
// Example: parse the UIC XML to find a key
async function fetchLevel1Key(
  securityProviderNum: number,
  keyId: number,
): Promise<Uint8Array> {
  const response = await fetch('https://railpublickey.uic.org/download.php');
  const xml = await response.text();

  // Parse XML and find matching <key> entry
  // Match on <issuerCode> === securityProviderNum AND <id> === keyId
  const keyBytes = findKeyInXml(xml, securityProviderNum, keyId);
  return keyBytes; // Base64-decoded <publicKey> value
}
```

#### Key Storage Formats

Public keys from the UIC registry can appear in two different formats
depending on how they were stored:

**Full SubjectPublicKeyInfo (SPKI) DER encoding (91 bytes for P-256):**

```
3059301306072a8648ce3d020106082a8648ce3d030107034200
04e3c5db6ad27110dde489f99037edcad2f594345cd4b3c354fdc87967c4c8ca
2a3e559ef3b26258c6531345ab8904704f35a3802318fc8cd1782f4e198da9c9
```

This is a complete DER-encoded SPKI structure containing the algorithm
identifier (ecPublicKey + namedCurve OID) followed by the uncompressed
public key point. The breakdown is:

- `3059...` — SEQUENCE wrapping AlgorithmIdentifier + BIT STRING
- `04e3c5...` — the uncompressed EC point (`04` prefix + Qx + Qy)

**Compressed EC point only (33 bytes for P-256):**

```
028f3d46312f69e918100e8c4ea1d3fb726d118271174fba406dd97e089c44d972
```

This is just the compressed EC point (`02` or `03` prefix + Qx coordinate).
The full point must be decompressed before use.

**Conversion may be needed** depending on which crypto library you use:

- **Web Crypto API** (`crypto.subtle.importKey`): Accepts raw uncompressed
  points (`04 || Qx || Qy`) with `format: 'raw'`, or full SPKI DER with
  `format: 'spki'`. Does **not** accept compressed points — you must
  decompress first.
- **Node.js `crypto`** (`createPublicKey`): Accepts SPKI DER with
  `format: 'der', type: 'spki'`. Also handles compressed points when
  building the SPKI wrapper.
- **`@noble/curves`**: Accepts both compressed and uncompressed points
  natively. No DER wrapping needed.

If you receive the full 91-byte SPKI DER but your library expects a raw
point, strip the 26-byte header to get the 65-byte uncompressed point.
If you receive a 33-byte compressed point but your library requires
uncompressed, use an EC point decompression function for the appropriate
curve.

#### Key Provider Interface

This should be handled via a callback/provider interface:

```typescript
interface Level1KeyProvider {
  getPublicKey(
    securityProvider: { num?: number; ia5?: string },
    keyId: number,
    keyAlg?: string,
  ): Promise<Uint8Array>;
}
```

---

## 5. Proposed API Design

### New file: `intercode6-ts/src/verifier.ts`

```typescript
/** Result of a signature verification attempt. */
interface SignatureVerificationResult {
  level1: {
    valid: boolean;
    error?: string;    // e.g. "missing signature", "unknown algorithm"
    algorithm?: string;
  };
  level2: {
    valid: boolean;
    error?: string;
    algorithm?: string;
  };
}

/** Options for signature verification. */
interface VerifyOptions {
  /** Provider for Level 1 public keys (looked up by issuer + keyId). */
  level1KeyProvider?: Level1KeyProvider;
  /**
   * Explicit Level 1 public key bytes.
   * Alternative to level1KeyProvider for simple cases.
   */
  level1PublicKey?: Uint8Array;
}

/**
 * Verify Level 1 and Level 2 signatures on a decoded UIC barcode.
 *
 * Level 2 verification uses the embedded level2PublicKey.
 * Level 1 verification requires an external key (via options).
 */
async function verifySignatures(
  bytes: Uint8Array,
  options?: VerifyOptions,
): Promise<SignatureVerificationResult>;

/**
 * Verify only the Level 2 signature (self-contained, no external key needed).
 */
async function verifyLevel2Signature(
  bytes: Uint8Array,
): Promise<{ valid: boolean; error?: string }>;

/**
 * Verify only the Level 1 signature.
 */
async function verifyLevel1Signature(
  bytes: Uint8Array,
  publicKey: Uint8Array,
): Promise<{ valid: boolean; error?: string }>;
```

### Usage Example

```typescript
import { decodeTicketFromBytes, verifySignatures } from 'intercode6-ts';

const bytes = /* barcode bytes */;

// Verify level 2 only (key is in the barcode)
const result = await verifySignatures(bytes);
console.log(result.level2.valid); // true/false

// Verify both levels with an explicit key
const result2 = await verifySignatures(bytes, {
  level1PublicKey: myLevel1Key,
});
console.log(result2.level1.valid); // true/false
console.log(result2.level2.valid); // true/false

// Or with a key provider
const result3 = await verifySignatures(bytes, {
  level1KeyProvider: {
    async getPublicKey(provider, keyId) {
      return fetchFromPKMW(provider.num, keyId);
    },
  },
});
```

---

## 6. Implementation Steps

### Step 1: OID mapping module (`src/oids.ts`)
- Map signing algorithm OIDs to hash + type
- Map key algorithm OIDs to curve/key type
- Export lookup functions

### Step 2: Signature format utilities (`src/signature-utils.ts`)
- `rawToDer(raw)` — convert (r || s) to DER for ECDSA/DSA
- `importEcPublicKey(raw, curve)` — parse raw EC point for use with `@noble/curves`
- `decompressEcPoint(compressed, curve)` — decompress EC point if needed
  (`@noble/curves` handles compressed points natively, so this may not
  be needed)

### Step 3: Signed data extraction (`src/signed-data.ts`)
- `extractSignedDataBytes(bytes, headerVersion)` — decode header via
  `headerCodec.decodeWithMetadata(bytes)`, then navigate the `DecodedNode`
  tree to extract `rawBytes` from the `level1Data` and `level2SignedData`
  nodes.  Returns `{ level1DataBytes, level2SignedBytes }`.
- Also extracts the decoded security fields (algorithm OIDs, embedded
  public key, signatures) from the same metadata tree using `stripMetadata`.
- No re-encoding or round-trip verification needed — bytes come directly
  from the source buffer.

### Step 4: Verification functions (`src/verifier.ts`)
- `verifyLevel1Signature(bytes, publicKey)` — extract level1Data bytes,
  get signing algorithm, verify signature
- `verifyLevel2Signature(bytes)` — extract level2SignedData bytes, import
  embedded public key, verify signature
- `verifySignatures(bytes, options)` — combined verification

### Step 5: Export and types
- Add `Level1KeyProvider` and `SignatureVerificationResult` to `types.ts`
- Export verification functions from `index.ts`

### Step 6: Tests
- Unit tests for OID mapping
- Unit tests for rawToDer conversion with known vectors
- Tests for signed data extraction via `decodeWithMetadata` (verify `rawBytes`
  offsets and lengths match expected sub-structure boundaries)
- Integration tests with real barcode samples (requires known-good keys)
- Test error cases (missing signatures, unknown algorithms, invalid keys)

---

## 7. Dependencies

### Requirement: Browser and Node.js Compatibility

The `intercode6-ts` module **must** work in both browser and Node.js
environments. This is a hard requirement — the module must not depend on
Node.js-only APIs such as `node:crypto` in its core code paths.

This means:
- No `import ... from 'node:crypto'` in library source code
- No `Buffer`-specific APIs (use `Uint8Array` throughout)
- No Node.js-specific globals (`process`, `__dirname`, etc.)
- The `fetch` API is available in both environments (Node.js 18+)

### Crypto Library Choice

Use `@noble/curves` (and `@noble/hashes`) for all cryptographic operations:
- **Zero native dependencies** — pure TypeScript, no C/C++ addons
- **Universal** — works in Node.js, browsers, Deno, and edge runtimes
- **Well-audited** — independently audited cryptographic library
- **Handles both compressed and uncompressed EC points** natively
- **No SPKI/DER wrapping needed** — operates directly on raw points

This avoids the need for separate Node.js (`node:crypto`) and browser
(`crypto.subtle`) code paths entirely.

For DSA/RSA support (less common among issuers), a fallback to the
Web Crypto API (`crypto.subtle`) can be used, since `crypto.subtle` is
available in both modern browsers and Node.js 16+.

---

## 8. Edge Cases and Considerations

1. **Missing signatures**: Either `level1Signature` or `level2Signature` may
   be absent (OPTIONAL in ASN.1). Return `{ valid: false, error: "missing" }`.

2. **Missing algorithm OIDs**: `level1SigningAlg` and `level2SigningAlg` are
   OPTIONAL. Without them, verification cannot proceed. Could fall back to
   inferring from key algorithm + signature size.

3. **Header version differences**: v1 and v2 have different `Level1DataType`
   schemas (v2 adds validity fields). The correct header schema must be
   used when calling `decodeWithMetadata` so the metadata tree structure
   matches the actual encoding.

4. **EC point compression**: `level2PublicKey` can be compressed (33 bytes)
   or uncompressed (65 bytes). The crypto library must handle both.

5. **Signature size validation**: ECDSA P-256 signatures should be 64 bytes
   (raw). Reject obviously wrong sizes early.

6. **DSA support**: Less common but specified. `@noble/curves` does not
   include DSA — use the Web Crypto API (`crypto.subtle`) as a fallback,
   which is available in both browsers and Node.js 16+.

7. **RSA support**: Some issuers may use RSA. RSA signatures and keys have
   variable sizes. PKCS#1 v1.5 vs PSS padding must be determined.

8. **~~Re-encoding fidelity~~ Eliminated**: Using `decodeWithMetadata`, the
   signed bytes are extracted directly from the source buffer via
   `rawBytes` in the metadata tree.  No re-encoding step exists, so
   codec normalisation cannot cause mismatches.  This was the highest-risk
   area in the original plan and is now a non-issue.

---

## 9. File Structure After Implementation

```
intercode6-ts/src/
├── types.ts           # + Level1KeyProvider, SignatureVerificationResult
├── index.ts           # + export verification functions
├── decoder.ts         # (unchanged)
├── encoder.ts         # (unchanged)
├── schemas.ts         # (unchanged)
├── fixtures.ts        # (unchanged)
├── oids.ts            # NEW: OID-to-algorithm mapping
├── signature-utils.ts # NEW: DER conversion, key import
├── signed-data.ts     # NEW: extract signed bytes via decodeWithMetadata
└── verifier.ts        # NEW: verification entry points

intercode6-ts/tests/
├── decoder.test.ts    # (unchanged)
├── oids.test.ts       # NEW
├── signature-utils.test.ts # NEW
├── signed-data.test.ts     # NEW
└── verifier.test.ts        # NEW
```

---

## 10. Summary of Key Decisions Needed

| Decision | Options | Recommendation |
|----------|---------|----------------|
| Crypto library | `@noble/curves` + Web Crypto fallback for DSA/RSA | `@noble/curves` (required: must work in both browser and Node.js) |
| Key provider interface | Sync vs async | Async (key lookup is typically a network call) |
| API granularity | Combined function vs separate level1/level2 | Both: combined `verifySignatures()` + individual `verifyLevel1/2Signature()` |
| Error reporting | Throw vs result object | Result object with `valid` + `error` fields |
| Browser support | Universal (required) | Must work in both browser and Node.js — no `node:crypto` dependency |
