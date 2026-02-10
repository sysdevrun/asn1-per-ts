import { importSpkiPublicKey } from '../src/signature-utils';
import { generateKeyPairSync } from 'node:crypto';

describe('importSpkiPublicKey', () => {
  it('imports a DSA SPKI public key', () => {
    const { publicKey } = generateKeyPairSync('dsa', {
      modulusLength: 1024,
      divisorLength: 160,
    });

    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const imported = importSpkiPublicKey(new Uint8Array(spkiDer));
    expect(imported.asymmetricKeyType).toBe('dsa');
  });

  it('imports an EC SPKI public key', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const imported = importSpkiPublicKey(new Uint8Array(spkiDer));
    expect(imported.asymmetricKeyType).toBe('ec');
  });
});
