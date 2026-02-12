import {
  parseKeysXml,
  extractPublicKeyFromDer,
  base64ToBytes,
  createUicKeyProvider,
} from '../src/key-provider';
import {
  verifySignatures,
  verifyLevel2Signature,
  decodeTicket,
  SAMPLE_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from '../src';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// Embedded UIC XML for offline testing (Région Grand Est keys)
const SAMPLE_UIC_XML = `<?xml version="1.0"?>
<keys>
  <key>
    <issuerName>Région Grand Est</issuerName>
    <issuerCode>3703</issuerCode>
    <versionType>DOS</versionType>
    <signatureAlgorithm>SHA256withECDSA</signatureAlgorithm>
    <id>7</id>
    <publicKey>MIIBTDCB86ADAgECAgkAtqDRe5tyMdAwCgYIKoZIzj0EAwIwLDENMAsGA1UEAwwEQ0IyRDEOMAwGA1UEBwwFUGFyaXMxCzAJBgNVBAYTAkZSMB4XDTI2MDIxMTIzMDAwMFoXDTI3MDgxMTIyMDAwMFowLDENMAsGA1UEAwwEQ0IyRDEOMAwGA1UEBwwFUGFyaXMxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMG5DBZ7oJ0lulLnD9AjFV+38McIGba2NE2wwL1CwgvIwe41DtnpU03/Fy6jynHlRkORQCGqQufPUl9obAI9SgjAKBggqhkjOPQQDAgNIADBFAiAHYYYT2zKZs7v4sakGMe/UIvX3yPXfX0thDMIeIVBfiwIhANtaENlU/KISUecforCrB6NhK3yjecWk0+Phn0cvp5sS</publicKey>
    <barcodeVersion>2</barcodeVersion>
    <startDate>2026-02-12</startDate>
    <endDate>2027-08-12</endDate>
  </key>
  <key>
    <issuerName>Région Grand Est</issuerName>
    <issuerCode>3703</issuerCode>
    <versionType>DOS</versionType>
    <signatureAlgorithm>SHA256withECDSA</signatureAlgorithm>
    <id>6</id>
    <publicKey>MIIBUTCB9aADAgECAgkAlMK7UAAJsf0wDAYIKoZIzj0EAwIFADAsMQswCQYDVQQGEwJGUjEOMAwGA1UEBxMFUGFyaXMxDTALBgNVBAMTBENCMkQwHhcNMjUwNTExMjIwMDAwWhcNMjYxMTExMjMwMDAwWjAsMQswCQYDVQQGEwJGUjEOMAwGA1UEBxMFUGFyaXMxDTALBgNVBAMTBENCMkQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARVl7ruK25yp4HeiOFBX2c1Pzy6ocdtalOqPG/o9WUMk+OHBFYqex2zbKIU2AJQMrlCaaDS2jnV3wE7a3YswuLMMAwGCCqGSM49BAMCBQADSQAwRgIhAPpVUh0G/nniDpj/E1PNRmhfCz2aSBv5Cn9XFyXkE6h/AiEAmc7uGGbja4z5hfoS3R2pDMIYjlNHk7UYZVy3JM523M0=</publicKey>
    <barcodeVersion>2</barcodeVersion>
    <startDate>2025-05-12</startDate>
    <endDate>2026-11-12</endDate>
  </key>
  <key>
    <issuerName>NS</issuerName>
    <issuerCode>1184</issuerCode>
    <versionType>TLB</versionType>
    <signatureAlgorithm>SHA1withDSA(1024,160)</signatureAlgorithm>
    <id>0022</id>
    <publicKey>MIICWzCCAhmgAwIBAgIIZolMnMGn15owCwYHKoZIzjgEAwUAMA8xDTALBgNVBAMTBEJFTkUwHhcNMjYwNDMwMjIwMDAwWhcNMjYxMjMwMjMwMDAwWjAPMQ0wCwYDVQQDEwRCRU5FMIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAd1r18jIBoC9ds5LjzNGUxxs4g6RjMX6QFSRhNOfiy7gQyGu55hir2Fuo6o6HZoOiXFKXLWtCZKp4jAyGraHXUkybTtps396BjsrVS4ik+p9bO2rQUwY408xOZmeMy5ApcbCdxrO18X/y+Cwv2G3bXmP07PbCChlPMjg7p1oqfW0wCwYHKoZIzjgEAwUAAy8AMCwCFFUDaKtwGPSCJLpuL81D/SVhvAa2AhR6Z9fMrZlNN3CF/Ai26otmqj6xyw==</publicKey>
    <barcodeVersion>1</barcodeVersion>
    <startDate>2026-05-01</startDate>
    <endDate>2026-12-31</endDate>
  </key>
</keys>`;

describe('parseKeysXml', () => {
  it('parses XML into key entries', () => {
    const entries = parseKeysXml(SAMPLE_UIC_XML);
    expect(entries).toHaveLength(3);

    expect(entries[0].issuerName).toBe('Région Grand Est');
    expect(entries[0].issuerCode).toBe(3703);
    expect(entries[0].id).toBe('7');
    expect(entries[0].signatureAlgorithm).toBe('SHA256withECDSA');
    expect(entries[0].barcodeVersion).toBe(2);
    expect(entries[0].publicKeyBase64).toContain('MIIBTDCB');
  });

  it('parses all issuer codes', () => {
    const entries = parseKeysXml(SAMPLE_UIC_XML);
    const codes = entries.map(e => e.issuerCode);
    expect(codes).toEqual([3703, 3703, 1184]);
  });

  it('parses key IDs correctly', () => {
    const entries = parseKeysXml(SAMPLE_UIC_XML);
    expect(entries[0].id).toBe('7');
    expect(entries[1].id).toBe('6');
    expect(entries[2].id).toBe('0022');
  });
});

describe('extractPublicKeyFromDer', () => {
  it('extracts EC P-256 public key from X.509 certificate', () => {
    // Grand Est key id=7 (SHA256withECDSA, P-256)
    const certB64 = 'MIIBTDCB86ADAgECAgkAtqDRe5tyMdAwCgYIKoZIzj0EAwIwLDENMAsGA1UEAwwEQ0IyRDEOMAwGA1UEBwwFUGFyaXMxCzAJBgNVBAYTAkZSMB4XDTI2MDIxMTIzMDAwMFoXDTI3MDgxMTIyMDAwMFowLDENMAsGA1UEAwwEQ0IyRDEOMAwGA1UEBwwFUGFyaXMxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMG5DBZ7oJ0lulLnD9AjFV+38McIGba2NE2wwL1CwgvIwe41DtnpU03/Fy6jynHlRkORQCGqQufPUl9obAI9SgjAKBggqhkjOPQQDAgNIADBFAiAHYYYT2zKZs7v4sakGMe/UIvX3yPXfX0thDMIeIVBfiwIhANtaENlU/KISUecforCrB6NhK3yjecWk0+Phn0cvp5sS';
    const certDer = base64ToBytes(certB64);
    const pubKey = extractPublicKeyFromDer(certDer);

    // P-256 uncompressed point: 04 || x(32) || y(32) = 65 bytes
    expect(pubKey.length).toBe(65);
    expect(pubKey[0]).toBe(0x04); // uncompressed point prefix
  });

  it('extracts EC P-256 public key from second Grand Est cert', () => {
    const certB64 = 'MIIBUTCB9aADAgECAgkAlMK7UAAJsf0wDAYIKoZIzj0EAwIFADAsMQswCQYDVQQGEwJGUjEOMAwGA1UEBxMFUGFyaXMxDTALBgNVBAMTBENCMkQwHhcNMjUwNTExMjIwMDAwWhcNMjYxMTExMjMwMDAwWjAsMQswCQYDVQQGEwJGUjEOMAwGA1UEBxMFUGFyaXMxDTALBgNVBAMTBENCMkQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARVl7ruK25yp4HeiOFBX2c1Pzy6ocdtalOqPG/o9WUMk+OHBFYqex2zbKIU2AJQMrlCaaDS2jnV3wE7a3YswuLMMAwGCCqGSM49BAMCBQADSQAwRgIhAPpVUh0G/nniDpj/E1PNRmhfCz2aSBv5Cn9XFyXkE6h/AiEAmc7uGGbja4z5hfoS3R2pDMIYjlNHk7UYZVy3JM523M0=';
    const certDer = base64ToBytes(certB64);
    const pubKey = extractPublicKeyFromDer(certDer);

    expect(pubKey.length).toBe(65);
    expect(pubKey[0]).toBe(0x04);
  });

  it('extracts DSA key from NS certificate', () => {
    const certB64 = 'MIICWzCCAhmgAwIBAgIIZolMnMGn15owCwYHKoZIzjgEAwUAMA8xDTALBgNVBAMTBEJFTkUwHhcNMjYwNDMwMjIwMDAwWhcNMjYxMjMwMjMwMDAwWjAPMQ0wCwYDVQQDEwRCRU5FMIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAd1r18jIBoC9ds5LjzNGUxxs4g6RjMX6QFSRhNOfiy7gQyGu55hir2Fuo6o6HZoOiXFKXLWtCZKp4jAyGraHXUkybTtps396BjsrVS4ik+p9bO2rQUwY408xOZmeMy5ApcbCdxrO18X/y+Cwv2G3bXmP07PbCChlPMjg7p1oqfW0wCwYHKoZIzjgEAwUAAy8AMCwCFFUDaKtwGPSCJLpuL81D/SVhvAa2AhR6Z9fMrZlNN3CF/Ai26otmqj6xyw==';
    const certDer = base64ToBytes(certB64);
    const pubKey = extractPublicKeyFromDer(certDer);

    // DSA key: DER-encoded INTEGER y (variable length, typically 128-132 bytes)
    expect(pubKey.length).toBeGreaterThan(100);
  });
});

describe('createUicKeyProvider', () => {
  it('looks up key by issuerCode and keyId', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });
    const key = await provider.getPublicKey({ num: 3703 }, 7);

    expect(key.length).toBe(65);
    expect(key[0]).toBe(0x04);
  });

  it('looks up key with string id (0022 → 22)', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });
    const key = await provider.getPublicKey({ num: 1184 }, 22);

    expect(key.length).toBeGreaterThan(0);
  });

  it('throws when key not found', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });
    await expect(
      provider.getPublicKey({ num: 3703 }, 999),
    ).rejects.toThrow('No public key found for issuerCode=3703, keyId=999');
  });

  it('throws when issuerCode not found', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });
    await expect(
      provider.getPublicKey({ num: 9999 }, 1),
    ).rejects.toThrow('No public key found for issuerCode=9999, keyId=1');
  });

  it('throws when security provider number is missing', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });
    await expect(
      provider.getPublicKey({}, 1),
    ).rejects.toThrow('Security provider number is required');
  });

  it('caches parsed entries across calls', async () => {
    const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });

    const key1 = await provider.getPublicKey({ num: 3703 }, 7);
    const key2 = await provider.getPublicKey({ num: 3703 }, 6);

    expect(key1.length).toBe(65);
    expect(key2.length).toBe(65);
    // Different keys for different ids
    expect(key1).not.toEqual(key2);
  });
});

describe('fixture signature verification with UIC keys', () => {
  const provider = createUicKeyProvider({ xml: SAMPLE_UIC_XML });

  it('sample ticket: issuerCode=3703, keyId=1, dummy signatures', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.security.securityProviderNum).toBe(3703);
    expect(ticket.security.keyId).toBe(1);
    expect(ticket.security.level1KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(ticket.security.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
    expect(ticket.security.level2KeyAlg).toBe('1.2.840.10045.3.1.7');
    // Sample has 33-byte compressed EC point as level2PublicKey
    expect(ticket.security.level2PublicKey!.length).toBe(33);
    // Dummy signatures (all 0x11 and 0x22)
    expect(ticket.security.level1Signature!.length).toBe(64);
    expect(ticket.level2Signature!.length).toBe(64);
  });

  it('Grand Est FCB3: issuerCode=3703, keyId=2, DER-encoded real signatures', () => {
    const ticket = decodeTicket(GRAND_EST_U1_FCB3_HEX);
    expect(ticket.security.securityProviderNum).toBe(3703);
    expect(ticket.security.keyId).toBe(2);
    expect(ticket.security.level1SigningAlg).toBe('1.2.840.10045.4.3.2');
    expect(ticket.security.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
    // Grand Est has 91-byte SPKI-wrapped P-256 key
    expect(ticket.security.level2PublicKey!.length).toBe(91);
    // DER-encoded ECDSA signatures (starts with 0x30)
    expect(ticket.security.level1Signature![0]).toBe(0x30);
    expect(ticket.level2Signature![0]).toBe(0x30);
  });

  it('sample ticket Level 2: identifies algorithm despite dummy signature', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);

    expect(result.algorithm).toBe('ECDSA-SHA-256 (P-256)');
    // Dummy signature (0x22 bytes) won't verify
    expect(result.valid).toBe(false);
  });

  it('Grand Est Level 2: identifies algorithm, handles SPKI key and DER signature', async () => {
    const bytes = hexToBytes(GRAND_EST_U1_FCB3_HEX);
    const result = await verifyLevel2Signature(bytes);

    expect(result.algorithm).toBe('ECDSA-SHA-256 (P-256)');
    // Signature verification runs without errors (no error field)
    expect(result.error).toBeUndefined();
    expect(typeof result.valid).toBe('boolean');
  });

  it('sample ticket Level 1: key not in UIC registry (keyId=1)', async () => {
    const bytes = hexToBytes(SAMPLE_TICKET_HEX);
    const result = await verifySignatures(bytes, { level1KeyProvider: provider });

    expect(result.level2.algorithm).toBe('ECDSA-SHA-256 (P-256)');
    expect(result.level1.valid).toBe(false);
    expect(result.level1.error).toContain('No public key found for issuerCode=3703, keyId=1');
  });

  it('Grand Est Level 1: key not in UIC registry (keyId=2)', async () => {
    const bytes = hexToBytes(GRAND_EST_U1_FCB3_HEX);
    const result = await verifySignatures(bytes, { level1KeyProvider: provider });

    expect(result.level2.algorithm).toBe('ECDSA-SHA-256 (P-256)');
    expect(result.level1.valid).toBe(false);
    expect(result.level1.error).toContain('No public key found for issuerCode=3703, keyId=2');
  });
});
