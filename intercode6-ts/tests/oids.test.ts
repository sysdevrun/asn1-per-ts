import {
  getSigningAlgorithm,
  getKeyAlgorithm,
  getSigningAlgorithmOids,
  getKeyAlgorithmOids,
} from '../src/oids';

describe('getSigningAlgorithm', () => {
  it('returns DSA with SHA-1 (FCB V1)', () => {
    const alg = getSigningAlgorithm('1.2.840.10040.4.3');
    expect(alg).toEqual({ hash: 'SHA-1', type: 'DSA' });
  });

  it('returns DSA with SHA-224 (FCB V2, DOSIPAS)', () => {
    const alg = getSigningAlgorithm('2.16.840.1.101.3.4.3.1');
    expect(alg).toEqual({ hash: 'SHA-224', type: 'DSA' });
  });

  it('returns DSA with SHA-256 (FCB V2, DOSIPAS)', () => {
    const alg = getSigningAlgorithm('2.16.840.1.101.3.4.3.2');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'DSA' });
  });

  it('returns ECDSA with SHA-256 (DOSIPAS)', () => {
    const alg = getSigningAlgorithm('1.2.840.10045.4.3.2');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'ECDSA' });
  });

  it('returns undefined for unknown OID', () => {
    expect(getSigningAlgorithm('1.2.3.4.5')).toBeUndefined();
  });

  it('does not include removed algorithms (RSA, ECDSA SHA-384/512)', () => {
    expect(getSigningAlgorithm('1.2.840.113549.1.1.11')).toBeUndefined(); // RSA
    expect(getSigningAlgorithm('1.2.840.10045.4.3.3')).toBeUndefined(); // ECDSA SHA-384
    expect(getSigningAlgorithm('1.2.840.10045.4.3.4')).toBeUndefined(); // ECDSA SHA-512
  });
});

describe('getKeyAlgorithm', () => {
  it('returns DSA', () => {
    const alg = getKeyAlgorithm('1.2.840.10040.4.1');
    expect(alg).toEqual({ type: 'DSA' });
  });

  it('returns EC P-256 (secp256r1)', () => {
    const alg = getKeyAlgorithm('1.2.840.10045.3.1.7');
    expect(alg).toEqual({ type: 'EC', curve: 'P-256' });
  });

  it('returns undefined for unknown OID', () => {
    expect(getKeyAlgorithm('9.9.9.9')).toBeUndefined();
  });

  it('does not include removed algorithms (RSA, P-384, P-521)', () => {
    expect(getKeyAlgorithm('1.2.840.113549.1.1.1')).toBeUndefined(); // RSA
    expect(getKeyAlgorithm('1.3.132.0.34')).toBeUndefined(); // P-384
    expect(getKeyAlgorithm('1.3.132.0.35')).toBeUndefined(); // P-521
  });
});

describe('OID listing', () => {
  it('lists all 4 signing algorithm OIDs', () => {
    const oids = getSigningAlgorithmOids();
    expect(oids).toContain('1.2.840.10040.4.3');     // DSA SHA-1
    expect(oids).toContain('2.16.840.1.101.3.4.3.1'); // DSA SHA-224
    expect(oids).toContain('2.16.840.1.101.3.4.3.2'); // DSA SHA-256
    expect(oids).toContain('1.2.840.10045.4.3.2');     // ECDSA SHA-256
    expect(oids.length).toBe(4);
  });

  it('lists all 2 key algorithm OIDs', () => {
    const oids = getKeyAlgorithmOids();
    expect(oids).toContain('1.2.840.10040.4.1');       // DSA
    expect(oids).toContain('1.2.840.10045.3.1.7');     // EC P-256
    expect(oids.length).toBe(2);
  });
});
