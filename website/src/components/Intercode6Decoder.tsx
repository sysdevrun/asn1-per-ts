import { useState, useEffect, useRef } from 'react';
import {
  decodeTicket,
  verifySignatures,
  createUicKeyProvider,
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from 'intercode6-ts';
import type { UicBarcodeTicket, SignatureLevelResult, SignatureVerificationResult } from 'intercode6-ts';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function formatDate(year: number, day: number): string {
  const d = new Date(year, 0, day);
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatTime(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
        <h4 className="text-sm font-semibold text-gray-700">{title}</h4>
      </div>
      <div className="p-4 space-y-1 text-sm">{children}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === undefined || value === null) return null;
  return (
    <div className="flex gap-2">
      <span className="text-gray-500 min-w-[180px]">{label}:</span>
      <span className="font-mono text-gray-900 break-all">{String(value)}</span>
    </div>
  );
}

function BytesField({ label, bytes }: { label: string; bytes?: Uint8Array }) {
  if (!bytes) return null;
  return (
    <div className="flex gap-2">
      <span className="text-gray-500 min-w-[180px]">{label}:</span>
      <span className="font-mono text-xs text-gray-700 break-all">
        [{bytes.length} bytes] {toHex(bytes)}
      </span>
    </div>
  );
}

function SignatureStatus({ label, result }: { label: string; result?: SignatureLevelResult | null }) {
  if (!result) return null;
  return (
    <div className="flex gap-2 items-start">
      <span className="text-gray-500 min-w-[180px]">{label}:</span>
      <span className="flex items-center gap-2">
        {result.valid ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
            Valid
          </span>
        ) : (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
            Invalid
          </span>
        )}
        {result.algorithm && (
          <span className="text-xs text-gray-500 font-mono">{result.algorithm}</span>
        )}
        {result.error && (
          <span className="text-xs text-red-500">{result.error}</span>
        )}
      </span>
    </div>
  );
}

function TicketDisplay({
  ticket,
  verificationResult,
  verifying,
}: {
  ticket: UicBarcodeTicket;
  verificationResult?: SignatureVerificationResult | null;
  verifying: boolean;
}) {
  return (
    <div className="space-y-4">
      <Section title="Header">
        <Field label="Format" value={ticket.format} />
        <Field label="Header version" value={ticket.headerVersion} />
        <BytesField label="Level 2 signature" bytes={ticket.level2Signature} />
      </Section>

      <Section title="Security & Signature Verification">
        <Field label="Security provider" value={ticket.security.securityProviderNum} />
        <Field label="Key ID" value={ticket.security.keyId} />
        <Field label="Level 1 key algorithm" value={ticket.security.level1KeyAlg} />
        <Field label="Level 2 key algorithm" value={ticket.security.level2KeyAlg} />
        <Field label="Level 1 signing algorithm" value={ticket.security.level1SigningAlg} />
        <Field label="Level 2 signing algorithm" value={ticket.security.level2SigningAlg} />
        <BytesField label="Level 2 public key" bytes={ticket.security.level2PublicKey} />
        <BytesField label="Level 1 signature" bytes={ticket.security.level1Signature} />

        <div className="mt-3 pt-3 border-t border-gray-100">
          <div className="text-xs font-semibold text-indigo-600 uppercase tracking-wide mb-2">
            Signature Verification
          </div>
          {verifying ? (
            <div className="text-xs text-gray-500">Verifying signatures...</div>
          ) : verificationResult ? (
            <>
              <SignatureStatus label="Level 2 (embedded key)" result={verificationResult.level2} />
              <SignatureStatus label="Level 1 (UIC registry)" result={verificationResult.level1} />
            </>
          ) : null}
        </div>
      </Section>

      {ticket.railTickets.map((rt, i) => (
        <div key={i} className="space-y-4">
          <Section title={`Rail Ticket (FCB${rt.fcbVersion})`}>
            {rt.issuingDetail && (
              <div className="space-y-1">
                <div className="text-xs font-semibold text-indigo-600 uppercase tracking-wide mb-1">
                  Issuing Detail
                </div>
                <Field label="Security provider" value={rt.issuingDetail.securityProviderNum} />
                <Field label="Issuer" value={rt.issuingDetail.issuerNum} />
                <Field label="Issuing date" value={
                  rt.issuingDetail.issuingYear && rt.issuingDetail.issuingDay
                    ? formatDate(rt.issuingDetail.issuingYear, rt.issuingDetail.issuingDay)
                    : undefined
                } />
                <Field label="Issuing year" value={rt.issuingDetail.issuingYear} />
                <Field label="Issuing day" value={rt.issuingDetail.issuingDay} />
                {rt.issuingDetail.issuingTime != null && (
                  <Field label="Issuing time" value={formatTime(rt.issuingDetail.issuingTime)} />
                )}
                <Field label="Issuer name" value={rt.issuingDetail.issuerName} />
                <Field label="Specimen" value={rt.issuingDetail.specimen ? 'Yes' : 'No'} />
                <Field label="Secure paper ticket" value={rt.issuingDetail.securePaperTicket ? 'Yes' : 'No'} />
                <Field label="Activated" value={rt.issuingDetail.activated ? 'Yes' : 'No'} />
                <Field label="Currency" value={rt.issuingDetail.currency} />
                <Field label="Currency fract" value={rt.issuingDetail.currencyFract} />
                <Field label="Issuer PNR" value={rt.issuingDetail.issuerPNR} />
              </div>
            )}

            {rt.issuingDetail?.intercodeIssuing && (
              <div className="mt-3 pt-3 border-t border-gray-100 space-y-1">
                <div className="text-xs font-semibold text-green-600 uppercase tracking-wide mb-1">
                  Intercode 6 Issuing Data
                </div>
                <Field label="Intercode version" value={rt.issuingDetail.intercodeIssuing.intercodeVersion} />
                <Field label="Intercode instanciation" value={rt.issuingDetail.intercodeIssuing.intercodeInstanciation} />
                <BytesField label="Network ID" bytes={rt.issuingDetail.intercodeIssuing.networkId} />
                {rt.issuingDetail.intercodeIssuing.productRetailer && (
                  <>
                    <Field label="Retail channel" value={rt.issuingDetail.intercodeIssuing.productRetailer.retailChannel} />
                    <Field label="Retail generator ID" value={rt.issuingDetail.intercodeIssuing.productRetailer.retailGeneratorId} />
                    <Field label="Retail server ID" value={rt.issuingDetail.intercodeIssuing.productRetailer.retailServerId} />
                    <Field label="Retailer ID" value={rt.issuingDetail.intercodeIssuing.productRetailer.retailerId} />
                    <Field label="Retail point ID" value={rt.issuingDetail.intercodeIssuing.productRetailer.retailPointId} />
                  </>
                )}
              </div>
            )}
          </Section>

          {rt.travelerDetail?.traveler && rt.travelerDetail.traveler.length > 0 && (
            <Section title="Travelers">
              {rt.travelerDetail.traveler.map((t, j) => (
                <div key={j} className="space-y-1">
                  <Field label="First name" value={t.firstName} />
                  <Field label="Last name" value={t.lastName} />
                  <Field label="Date of birth" value={t.dateOfBirth} />
                  <Field label="Gender" value={t.gender} />
                  <Field label="Ticket holder" value={t.ticketHolder != null ? (t.ticketHolder ? 'Yes' : 'No') : undefined} />
                </div>
              ))}
            </Section>
          )}

          {rt.transportDocument && rt.transportDocument.length > 0 && (
            <Section title={`Transport Documents (${rt.transportDocument.length})`}>
              {rt.transportDocument.map((doc, j) => (
                <div key={j} className="space-y-1">
                  <div className="text-xs font-semibold text-indigo-600 uppercase tracking-wide mb-1">
                    {doc.ticketType}
                  </div>
                  <pre className="text-xs font-mono bg-gray-50 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap">
                    {JSON.stringify(doc.ticket, (_k, v) =>
                      v instanceof Uint8Array ? `[${v.length} bytes] ${toHex(v)}` : v
                    , 2)}
                  </pre>
                </div>
              ))}
            </Section>
          )}

          {rt.controlDetail && (
            <Section title="Control Detail">
              <pre className="text-xs font-mono bg-gray-50 rounded p-3 overflow-auto max-h-48 whitespace-pre-wrap">
                {JSON.stringify(rt.controlDetail, null, 2)}
              </pre>
            </Section>
          )}
        </div>
      ))}

      {ticket.dynamicData && (
        <Section title="Intercode 6 Dynamic Data">
          <Field label="Dynamic content day" value={ticket.dynamicData.dynamicContentDay} />
          {ticket.dynamicData.dynamicContentTime != null && (
            <Field label="Dynamic content time" value={ticket.dynamicData.dynamicContentTime} />
          )}
          <Field label="UTC offset" value={ticket.dynamicData.dynamicContentUTCOffset} />
          <Field label="Duration" value={ticket.dynamicData.dynamicContentDuration} />
          {ticket.level2DataBlock && (
            <Field label="Data format" value={ticket.level2DataBlock.dataFormat} />
          )}
        </Section>
      )}

      {ticket.otherDataBlocks.length > 0 && (
        <Section title="Other Data Blocks">
          {ticket.otherDataBlocks.map((block, i) => (
            <div key={i}>
              <Field label="Format" value={block.dataFormat} />
              <BytesField label="Data" bytes={block.data} />
            </div>
          ))}
        </Section>
      )}

      <Section title="Raw Decoded Data">
        <pre className="text-xs font-mono bg-gray-50 rounded p-3 overflow-auto max-h-96 whitespace-pre-wrap">
          {JSON.stringify(ticket, (_k, v) =>
            v instanceof Uint8Array ? `[${v.length} bytes] ${toHex(v)}` : v
          , 2)}
        </pre>
      </Section>
    </div>
  );
}

interface Intercode6DecoderProps {
  initialHex?: string;
  onConsumeInitialHex?: () => void;
}

export default function Intercode6Decoder({ initialHex, onConsumeInitialHex }: Intercode6DecoderProps) {
  const [hexInput, setHexInput] = useState('');
  const [ticket, setTicket] = useState<UicBarcodeTicket | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [consumedHex, setConsumedHex] = useState<string | undefined>(undefined);
  const [verificationResult, setVerificationResult] = useState<SignatureVerificationResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const keyProviderRef = useRef(createUicKeyProvider());

  // Run signature verification when ticket changes
  useEffect(() => {
    if (!ticket) {
      setVerificationResult(null);
      return;
    }

    let cancelled = false;
    setVerifying(true);

    const hex = hexInput.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
    if (!hex || hex.length % 2 !== 0) {
      setVerifying(false);
      return;
    }

    const bytes = hexToBytes(hex);
    verifySignatures(bytes, { level1KeyProvider: keyProviderRef.current }).then((result) => {
      if (!cancelled) {
        setVerificationResult(result);
        setVerifying(false);
      }
    }).catch(() => {
      if (!cancelled) {
        setVerificationResult({
          level1: { valid: false, error: 'Verification failed unexpectedly' },
          level2: { valid: false, error: 'Verification failed unexpectedly' },
        });
        setVerifying(false);
      }
    });

    return () => { cancelled = true; };
  }, [ticket, hexInput]);

  // Auto-decode when initialHex is provided from Aztec reader
  if (initialHex && initialHex !== consumedHex) {
    setConsumedHex(initialHex);
    setHexInput(initialHex);
    setError(null);
    setTicket(null);
    try {
      const decoded = decodeTicket(initialHex);
      setTicket(decoded);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Decoding failed');
    }
    onConsumeInitialHex?.();
  }

  const handleDecode = (hex?: string) => {
    const input = hex ?? hexInput;
    setError(null);
    setTicket(null);
    setVerificationResult(null);
    try {
      if (!input.trim()) {
        setError('Enter hex data to decode');
        return;
      }
      const decoded = decodeTicket(input);
      setTicket(decoded);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Decoding failed');
    }
  };

  const handleLoadPreset = (hex: string) => {
    setHexInput(hex);
    handleDecode(hex);
  };

  return (
    <section>
      <h2 className="text-xl font-semibold mb-4">Intercode 6 Ticket Decoder</h2>
      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        <p className="text-sm text-gray-600">
          Paste hex-encoded UIC barcode data below to decode a rail ticket with Intercode 6 extensions.
        </p>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleLoadPreset(SAMPLE_TICKET_HEX)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            Sample FCB2
          </button>
          <button
            onClick={() => handleLoadPreset(SNCF_TER_TICKET_HEX)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            SNCF TER
          </button>
          <button
            onClick={() => handleLoadPreset(SOLEA_TICKET_HEX)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            Soléa
          </button>
          <button
            onClick={() => handleLoadPreset(CTS_TICKET_HEX)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            CTS
          </button>
          <button
            onClick={() => handleLoadPreset(GRAND_EST_U1_FCB3_HEX)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            Grand Est FCB3
          </button>
        </div>

        <textarea
          value={hexInput}
          onChange={(e) => setHexInput(e.target.value)}
          spellCheck={false}
          className="w-full h-32 font-mono text-xs p-4 border border-gray-300 rounded-lg resize-y bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-300"
          placeholder="Paste hex-encoded UIC barcode data here..."
        />

        <button
          onClick={() => handleDecode()}
          className="px-5 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors"
        >
          Decode Ticket
        </button>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-600 text-sm">{error}</p>
          </div>
        )}

        {ticket && (
          <TicketDisplay
            ticket={ticket}
            verificationResult={verificationResult}
            verifying={verifying}
          />
        )}
      </div>
    </section>
  );
}
