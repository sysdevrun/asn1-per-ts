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

### Approach

The header schema JSON (`uicBarcodeHeader_v1.schema.json`,
`uicBarcodeHeader_v2.schema.json`) already exports standalone named types
`Level1DataType` and `Level2DataType`. We can build codecs for these
sub-structures and re-encode the decoded objects:

```typescript
// Build codecs for the sub-structures
const schemas = HEADER_SCHEMAS[headerVersion];
const codecs = SchemaBuilder.buildAll(schemas);

// Re-encode level1Data → bytes that were signed by level1Signature
const level1DataCodec = new SchemaCodec(schemas.Level1DataType);
const level1DataBytes = level1DataCodec.encode(header.level2SignedData.level1Data);

// Re-encode level2SignedData → bytes that were signed by level2Signature
const level2DataCodec = new SchemaCodec(schemas.Level2DataType);
const level2SignedBytes = level2DataCodec.encode(header.level2SignedData);
```

### Verification Required

Round-trip accuracy must be verified: decode a known barcode, re-encode the
sub-structures, and confirm the bytes match the original PER encoding. This
is critical because any bit-level difference will cause signature verification
to fail.

**Risk**: If the decoder normalizes or drops any optional fields during
decoding, re-encoding could produce different bytes. The decoder must
preserve the raw decoded object (not the typed extraction) for re-encoding.
The current decoder already has access to the raw `header` object, so
this should work.

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

Node.js `crypto.verify()` expects **DER-encoded** signatures. A conversion
is needed:

```
Raw:  r (32 bytes) || s (32 bytes)  → 64 bytes total
DER:  SEQUENCE { INTEGER r, INTEGER s }  → ~70-72 bytes
```

### Implementation

```typescript
// Convert raw (r || s) to DER-encoded ECDSA signature
function rawToDer(raw: Uint8Array): Buffer {
  const half = raw.length / 2;
  const r = raw.slice(0, half);
  const s = raw.slice(half);

  function encodeInteger(value: Uint8Array): Buffer {
    // Strip leading zeros, add 0x00 padding if high bit set
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    const trimmed = value.slice(start);
    const needsPad = trimmed[0] & 0x80;
    const len = trimmed.length + (needsPad ? 1 : 0);
    const buf = Buffer.alloc(2 + len);
    buf[0] = 0x02; // INTEGER tag
    buf[1] = len;
    if (needsPad) buf[2] = 0x00;
    buf.set(trimmed, 2 + (needsPad ? 1 : 0));
    return buf;
  }

  const rDer = encodeInteger(r);
  const sDer = encodeInteger(s);
  const seq = Buffer.alloc(2 + rDer.length + sDer.length);
  seq[0] = 0x30; // SEQUENCE tag
  seq[1] = rDer.length + sDer.length;
  seq.set(rDer, 2);
  seq.set(sDer, 2 + rDer.length);
  return seq;
}
```

### DSA Signature Format

DSA signatures also use (r || s) concatenation in UIC barcodes and need
the same DER conversion.

---

## 4. Public Key Handling

### Level 2 Public Key (embedded in barcode)

The `level2PublicKey` field contains a raw EC public key in one of two forms:

- **Uncompressed** (65 bytes for P-256): `04 || Qx (32) || Qy (32)`
- **Compressed** (33 bytes for P-256): `02|03 || Qx (32)`

To use with Node.js `crypto`, the raw key bytes need to be wrapped in a
SubjectPublicKeyInfo (SPKI) DER structure, or imported via `crypto.createPublicKey()`
with appropriate format specification.

```typescript
import { createPublicKey } from 'node:crypto';

function importEcPublicKey(raw: Uint8Array, curve: string): crypto.KeyObject {
  // Build uncompressed point → SPKI DER wrapper
  // The SPKI structure for EC keys is:
  //   SEQUENCE {
  //     SEQUENCE { OID ecPublicKey, OID namedCurve }
  //     BIT STRING (public key point)
  //   }
  // Or use createPublicKey with JWK format after converting point to x/y
  return createPublicKey({
    key: buildSpkiDer(raw, curve),
    format: 'der',
    type: 'spki',
  });
}
```

**Alternative**: Use the Web Crypto API (`crypto.subtle`) for browser
compatibility. This accepts raw key import via `importKey('raw', ...)` for
EC keys directly, avoiding manual SPKI construction.

### Level 1 Public Key (external lookup)

The level 1 public key is **not in the barcode**. It must be fetched from a
key management system (UIC PKMW - Public Key Management Webservice) using:

- `securityProviderNum` (or `securityProviderIA5`) — identifies the issuer
- `keyId` — identifies which key

This should be handled via a callback/provider interface:

```typescript
interface Level1KeyProvider {
  getPublicKey(
    securityProvider: { num?: number; ia5?: string },
    keyId: number,
    keyAlg?: string,
  ): Promise<Uint8Array | crypto.KeyObject>;
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
  publicKey: Uint8Array | crypto.KeyObject,
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
- `importEcPublicKey(raw, curve)` — wrap raw EC point in SPKI and import
- `decompressEcPoint(compressed, curve)` — decompress EC point if needed
  (Node.js `createPublicKey` handles compressed points natively, so this
  may not be needed)

### Step 3: Signed data extraction (`src/signed-data.ts`)
- `extractLevel1DataBytes(bytes, headerVersion)` — decode full header,
  re-encode `level1Data` using `Level1DataType` schema
- `extractLevel2SignedDataBytes(bytes, headerVersion)` — decode full header,
  re-encode `level2SignedData` using `Level2DataType` schema
- Round-trip tests to verify byte-exact re-encoding

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
- Round-trip tests for signed data extraction (decode → re-encode → compare)
- Integration tests with real barcode samples (requires known-good keys)
- Test error cases (missing signatures, unknown algorithms, invalid keys)

---

## 7. Dependencies

### Required
- **Node.js `crypto` module** (built-in) — for `createVerify`, `createPublicKey`
  - No additional npm dependencies needed for Node.js environments

### Browser Compatibility Consideration
- Node.js `crypto` is not available in browsers
- For browser support, use Web Crypto API (`crypto.subtle.verify`,
  `crypto.subtle.importKey`)
- Could use a runtime check or provide separate entry points:
  - `verifier.ts` (Node.js, uses `node:crypto`)
  - `verifier.browser.ts` (browser, uses `crypto.subtle`)
- Or use a universal library like `@noble/curves` which works in both
  environments with zero dependencies

### Recommendation
Use `@noble/curves` (or `@noble/secp256k1` / `@noble/hashes`) for:
- Zero native dependencies
- Works in Node.js, browsers, and edge runtimes
- Pure TypeScript
- Well-audited cryptographic library
- Handles both compressed and uncompressed EC points natively

---

## 8. Edge Cases and Considerations

1. **Missing signatures**: Either `level1Signature` or `level2Signature` may
   be absent (OPTIONAL in ASN.1). Return `{ valid: false, error: "missing" }`.

2. **Missing algorithm OIDs**: `level1SigningAlg` and `level2SigningAlg` are
   OPTIONAL. Without them, verification cannot proceed. Could fall back to
   inferring from key algorithm + signature size.

3. **Header version differences**: v1 and v2 have different `Level1DataType`
   schemas (v2 adds validity fields). The correct schema must be used for
   re-encoding.

4. **EC point compression**: `level2PublicKey` can be compressed (33 bytes)
   or uncompressed (65 bytes). The crypto library must handle both.

5. **Signature size validation**: ECDSA P-256 signatures should be 64 bytes
   (raw). Reject obviously wrong sizes early.

6. **DSA support**: Less common but specified. Node.js `crypto` supports DSA
   natively. `@noble/curves` does not include DSA — would need a separate
   library or Node.js crypto fallback.

7. **RSA support**: Some issuers may use RSA. RSA signatures and keys have
   variable sizes. PKCS#1 v1.5 vs PSS padding must be determined.

8. **Re-encoding fidelity**: The PER re-encoding of decoded data must produce
   byte-identical output. This is the highest-risk area. If any codec
   normalizes values (e.g., trims leading zeros from integers, reorders
   fields), verification will fail. The existing per-unaligned-ts library
   should handle this correctly since PER is a canonical encoding, but it
   must be tested.

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
├── signed-data.ts     # NEW: extract PER-encoded sub-structures
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
| Crypto library | Node.js `crypto` vs `@noble/curves` vs Web Crypto | `@noble/curves` for universality, with `node:crypto` fallback for DSA/RSA |
| Key provider interface | Sync vs async | Async (key lookup is typically a network call) |
| API granularity | Combined function vs separate level1/level2 | Both: combined `verifySignatures()` + individual `verifyLevel1/2Signature()` |
| Error reporting | Throw vs result object | Result object with `valid` + `error` fields |
| Browser support | Node-only vs universal | Universal via `@noble/curves` for EC, defer DSA/RSA browser support |
