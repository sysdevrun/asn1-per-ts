import {
  getSigningAlgorithm,
  getKeyAlgorithm,
  getSigningAlgorithmOids,
  getKeyAlgorithmOids,
} from '../src/oids';

describe('getSigningAlgorithm', () => {
  it('returns ECDSA with SHA-256 for the correct OID', () => {
    const alg = getSigningAlgorithm('1.2.840.10045.4.3.2');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'ECDSA' });
  });

  it('returns ECDSA with SHA-384', () => {
    const alg = getSigningAlgorithm('1.2.840.10045.4.3.3');
    expect(alg).toEqual({ hash: 'SHA-384', type: 'ECDSA' });
  });

  it('returns ECDSA with SHA-512', () => {
    const alg = getSigningAlgorithm('1.2.840.10045.4.3.4');
    expect(alg).toEqual({ hash: 'SHA-512', type: 'ECDSA' });
  });

  it('returns DSA with SHA-224', () => {
    const alg = getSigningAlgorithm('2.16.840.1.101.3.4.3.1');
    expect(alg).toEqual({ hash: 'SHA-224', type: 'DSA' });
  });

  it('returns DSA with SHA-256', () => {
    const alg = getSigningAlgorithm('2.16.840.1.101.3.4.3.2');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'DSA' });
  });

  it('returns RSA with SHA-256', () => {
    const alg = getSigningAlgorithm('1.2.840.113549.1.1.11');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'RSA' });
  });

  it('returns undefined for unknown OID', () => {
    expect(getSigningAlgorithm('1.2.3.4.5')).toBeUndefined();
  });
});

describe('getKeyAlgorithm', () => {
  it('returns EC P-256 (secp256r1)', () => {
    const alg = getKeyAlgorithm('1.2.840.10045.3.1.7');
    expect(alg).toEqual({ type: 'EC', curve: 'P-256' });
  });

  it('returns EC P-384 (secp384r1)', () => {
    const alg = getKeyAlgorithm('1.3.132.0.34');
    expect(alg).toEqual({ type: 'EC', curve: 'P-384' });
  });

  it('returns EC P-521 (secp521r1)', () => {
    const alg = getKeyAlgorithm('1.3.132.0.35');
    expect(alg).toEqual({ type: 'EC', curve: 'P-521' });
  });

  it('returns RSA', () => {
    const alg = getKeyAlgorithm('1.2.840.113549.1.1.1');
    expect(alg).toEqual({ type: 'RSA' });
  });

  it('returns undefined for unknown OID', () => {
    expect(getKeyAlgorithm('9.9.9.9')).toBeUndefined();
  });
});

describe('OID listing', () => {
  it('lists all signing algorithm OIDs', () => {
    const oids = getSigningAlgorithmOids();
    expect(oids).toContain('1.2.840.10045.4.3.2');
    expect(oids).toContain('1.2.840.113549.1.1.11');
    expect(oids.length).toBe(6);
  });

  it('lists all key algorithm OIDs', () => {
    const oids = getKeyAlgorithmOids();
    expect(oids).toContain('1.2.840.10045.3.1.7');
    expect(oids).toContain('1.2.840.113549.1.1.1');
    expect(oids.length).toBe(4);
  });
});
