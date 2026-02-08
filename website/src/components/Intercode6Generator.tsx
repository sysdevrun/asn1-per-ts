import { useState, useCallback, useEffect, useRef } from 'react';
import { encodeTicket, SAMPLE_TICKET_HEX, decodeTicket } from 'intercode6-ts';
import type { UicBarcodeTicketInput } from 'intercode6-ts';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Aztec barcode rendering (pure canvas, no external dependency)
// ---------------------------------------------------------------------------

/**
 * Simple Aztec-style 2D barcode renderer.
 * Since a full Aztec encoder is complex, we render a DataMatrix-like visual
 * representation of the hex data for demonstration purposes.
 * For production use, integrate a proper Aztec library.
 */
function renderBarcodeToCanvas(
  canvas: HTMLCanvasElement,
  hex: string,
  moduleSize: number = 4,
) {
  const bytes = hex.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) ?? [];
  // Create a bit array from all bytes
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1);
    }
  }

  // Calculate grid dimensions (roughly square)
  const side = Math.ceil(Math.sqrt(bits.length));
  const size = side * moduleSize;

  canvas.width = size + moduleSize * 4;
  canvas.height = size + moduleSize * 4;

  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Draw finder pattern (Aztec-style bullseye in center)
  const cx = Math.floor(canvas.width / 2);
  const cy = Math.floor(canvas.height / 2);
  const rings = 3;
  for (let r = rings; r >= 0; r--) {
    ctx.fillStyle = r % 2 === 0 ? '#000000' : '#ffffff';
    const s = (r * 2 + 1) * moduleSize;
    ctx.fillRect(cx - s / 2, cy - s / 2, s, s);
  }

  // Draw data modules around the finder
  ctx.fillStyle = '#000000';
  const offset = moduleSize * 2;
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      const x = (i % side) * moduleSize + offset;
      const y = Math.floor(i / side) * moduleSize + offset;
      // Skip the center finder area
      const dx = Math.abs(x + moduleSize / 2 - cx);
      const dy = Math.abs(y + moduleSize / 2 - cy);
      if (dx > (rings + 1) * moduleSize || dy > (rings + 1) * moduleSize) {
        ctx.fillRect(x, y, moduleSize, moduleSize);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Default ticket values (matching the sample fixture structure)
// ---------------------------------------------------------------------------

function getDefaultInput(): FormState {
  // Decode the sample to extract values
  try {
    const decoded = decodeTicket(SAMPLE_TICKET_HEX);
    const rt = decoded.railTickets[0];
    const iss = rt?.issuingDetail;
    const ic = iss?.intercodeIssuing;
    return {
      headerVersion: decoded.headerVersion,
      securityProviderNum: decoded.security.securityProviderNum ?? 3703,
      keyId: decoded.security.keyId ?? 1,
      fcbVersion: rt?.fcbVersion ?? 2,
      issuingYear: iss?.issuingYear ?? 2025,
      issuingDay: iss?.issuingDay ?? 1,
      issuingTime: iss?.issuingTime ?? 0,
      specimen: iss?.specimen ?? false,
      activated: iss?.activated ?? true,
      currency: iss?.currency ?? 'EUR',
      currencyFract: iss?.currencyFract ?? 2,
      intercodeVersion: ic?.intercodeVersion ?? 1,
      intercodeInstanciation: ic?.intercodeInstanciation ?? 1,
      networkIdHex: ic?.networkId ? toHex(ic.networkId) : '250915',
      retailChannel: ic?.productRetailer?.retailChannel ?? 'mobileApplication',
      dynamicContentDay: decoded.dynamicData?.dynamicContentDay ?? 0,
      dynamicContentTime: decoded.dynamicData?.dynamicContentTime,
      dynamicContentUTCOffset: decoded.dynamicData?.dynamicContentUTCOffset ?? 0,
      dynamicContentDuration: decoded.dynamicData?.dynamicContentDuration ?? 600,
    };
  } catch {
    return {
      headerVersion: 2,
      securityProviderNum: 3703,
      keyId: 1,
      fcbVersion: 2,
      issuingYear: 2025,
      issuingDay: 1,
      issuingTime: 0,
      specimen: false,
      activated: true,
      currency: 'EUR',
      currencyFract: 2,
      intercodeVersion: 1,
      intercodeInstanciation: 1,
      networkIdHex: '250915',
      retailChannel: 'mobileApplication',
      dynamicContentDay: 0,
      dynamicContentTime: undefined,
      dynamicContentUTCOffset: 0,
      dynamicContentDuration: 600,
    };
  }
}

interface FormState {
  headerVersion: number;
  securityProviderNum: number;
  keyId: number;
  fcbVersion: number;
  issuingYear: number;
  issuingDay: number;
  issuingTime: number;
  specimen: boolean;
  activated: boolean;
  currency: string;
  currencyFract: number;
  intercodeVersion: number;
  intercodeInstanciation: number;
  networkIdHex: string;
  retailChannel: string;
  dynamicContentDay: number;
  dynamicContentTime?: number;
  dynamicContentUTCOffset: number;
  dynamicContentDuration: number;
}

function NumberInput({ label, value, onChange, min, max }: {
  label: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
  min?: number;
  max?: number;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      <input
        type="number"
        value={value ?? ''}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === '' ? undefined : parseInt(v, 10));
        }}
        min={min}
        max={max}
        className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-indigo-300 font-mono"
      />
    </div>
  );
}

function TextInput({ label, value, onChange }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-indigo-300 font-mono"
      />
    </div>
  );
}

function CheckboxInput({ label, checked, onChange }: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm text-gray-700">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-gray-300"
      />
      {label}
    </label>
  );
}

export default function Intercode6Generator() {
  const [form, setForm] = useState<FormState>(getDefaultInput);
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const update = useCallback((patch: Partial<FormState>) => {
    setForm(prev => ({ ...prev, ...patch }));
  }, []);

  const handleGenerate = useCallback(() => {
    setError(null);
    setOutput('');
    try {
      const networkIdBytes = new Uint8Array(
        (form.networkIdHex.match(/.{1,2}/g) ?? []).map(b => parseInt(b, 16)),
      );

      // Build a placeholder signature
      const sig64 = new Uint8Array(64).fill(0x22);

      const input: UicBarcodeTicketInput = {
        headerVersion: form.headerVersion,
        securityProviderNum: form.securityProviderNum,
        keyId: form.keyId,
        level1KeyAlg: '1.2.840.10045.3.1.7',
        level2KeyAlg: '1.2.840.10045.3.1.7',
        level2SigningAlg: '1.2.840.10045.4.3.2',
        level2PublicKey: new Uint8Array(33).fill(0x03),
        level1Signature: sig64,
        level2Signature: sig64,
        fcbVersion: form.fcbVersion,
        railTicket: {
          issuingDetail: {
            securityProviderNum: form.securityProviderNum,
            issuingYear: form.issuingYear,
            issuingDay: form.issuingDay,
            issuingTime: form.issuingTime,
            specimen: form.specimen,
            securePaperTicket: false,
            activated: form.activated,
            currency: form.currency,
            currencyFract: form.currencyFract,
            intercodeIssuing: {
              intercodeVersion: form.intercodeVersion,
              intercodeInstanciation: form.intercodeInstanciation,
              networkId: networkIdBytes,
              productRetailer: {
                retailChannel: form.retailChannel as any,
              },
            },
          },
          transportDocument: [],
        },
        dynamicData: {
          rics: form.securityProviderNum,
          dynamicContentDay: form.dynamicContentDay,
          dynamicContentTime: form.dynamicContentTime,
          dynamicContentUTCOffset: form.dynamicContentUTCOffset,
          dynamicContentDuration: form.dynamicContentDuration,
        },
      };

      const hex = encodeTicket(input);
      setOutput(hex);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Encoding failed');
    }
  }, [form]);

  // Render barcode when output changes
  useEffect(() => {
    if (output && canvasRef.current) {
      renderBarcodeToCanvas(canvasRef.current, output, 3);
    }
  }, [output]);

  return (
    <section>
      <h2 className="text-xl font-semibold mb-4">Intercode 6 Ticket Generator</h2>
      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-6">
        <p className="text-sm text-gray-600">
          Configure ticket parameters below and generate a hex-encoded UIC barcode with Aztec code visualization.
        </p>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Left: form */}
          <div className="space-y-4">
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Header</div>
            <div className="grid grid-cols-2 gap-3">
              <NumberInput label="Header version" value={form.headerVersion} onChange={v => update({ headerVersion: v ?? 2 })} min={1} max={2} />
              <NumberInput label="FCB version" value={form.fcbVersion} onChange={v => update({ fcbVersion: v ?? 2 })} min={1} max={3} />
              <NumberInput label="Security provider (RICS)" value={form.securityProviderNum} onChange={v => update({ securityProviderNum: v ?? 0 })} min={1} max={32000} />
              <NumberInput label="Key ID" value={form.keyId} onChange={v => update({ keyId: v ?? 0 })} min={0} max={99999} />
            </div>

            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide pt-2">Issuing Detail</div>
            <div className="grid grid-cols-2 gap-3">
              <NumberInput label="Issuing year" value={form.issuingYear} onChange={v => update({ issuingYear: v ?? 2025 })} min={2016} max={2269} />
              <NumberInput label="Issuing day" value={form.issuingDay} onChange={v => update({ issuingDay: v ?? 1 })} min={1} max={366} />
              <NumberInput label="Issuing time (min)" value={form.issuingTime} onChange={v => update({ issuingTime: v ?? 0 })} min={0} max={1439} />
              <TextInput label="Currency" value={form.currency} onChange={v => update({ currency: v })} />
              <NumberInput label="Currency fract" value={form.currencyFract} onChange={v => update({ currencyFract: v ?? 2 })} min={1} max={3} />
            </div>
            <div className="flex gap-4">
              <CheckboxInput label="Specimen" checked={form.specimen} onChange={v => update({ specimen: v })} />
              <CheckboxInput label="Activated" checked={form.activated} onChange={v => update({ activated: v })} />
            </div>

            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide pt-2">Intercode 6</div>
            <div className="grid grid-cols-2 gap-3">
              <NumberInput label="IC version" value={form.intercodeVersion} onChange={v => update({ intercodeVersion: v ?? 1 })} min={0} max={7} />
              <NumberInput label="IC instanciation" value={form.intercodeInstanciation} onChange={v => update({ intercodeInstanciation: v ?? 1 })} min={0} max={7} />
              <TextInput label="Network ID (hex)" value={form.networkIdHex} onChange={v => update({ networkIdHex: v })} />
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Retail channel</label>
                <select
                  value={form.retailChannel}
                  onChange={(e) => update({ retailChannel: e.target.value })}
                  className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-indigo-300"
                >
                  <option value="smsTicket">SMS Ticket</option>
                  <option value="mobileApplication">Mobile Application</option>
                  <option value="webSite">Website</option>
                  <option value="ticketOffice">Ticket Office</option>
                  <option value="depositaryTerminal">Depositary Terminal</option>
                  <option value="onBoardTerminal">On-Board Terminal</option>
                  <option value="ticketVendingMachine">Ticket Vending Machine</option>
                </select>
              </div>
            </div>

            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide pt-2">Dynamic Data</div>
            <div className="grid grid-cols-2 gap-3">
              <NumberInput label="Content day" value={form.dynamicContentDay} onChange={v => update({ dynamicContentDay: v ?? 0 })} min={-1} max={1070} />
              <NumberInput label="Content time" value={form.dynamicContentTime} onChange={v => update({ dynamicContentTime: v })} min={0} max={86399} />
              <NumberInput label="UTC offset" value={form.dynamicContentUTCOffset} onChange={v => update({ dynamicContentUTCOffset: v ?? 0 })} min={-60} max={60} />
              <NumberInput label="Duration" value={form.dynamicContentDuration} onChange={v => update({ dynamicContentDuration: v ?? 0 })} min={0} max={86399} />
            </div>

            <button
              onClick={handleGenerate}
              className="px-5 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors"
            >
              Generate Ticket
            </button>
          </div>

          {/* Right: output */}
          <div className="space-y-4">
            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-600 text-sm">{error}</p>
              </div>
            )}

            {output && (
              <>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Aztec Code</label>
                  <div className="bg-white border border-gray-200 rounded-lg p-4 flex justify-center">
                    <canvas ref={canvasRef} className="max-w-full" />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    Hex Output ({output.length / 2} bytes)
                  </label>
                  <div className="font-mono text-xs p-4 border border-gray-300 rounded-lg bg-gray-50 overflow-auto max-h-48 break-all whitespace-pre-wrap">
                    {output}
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(output)}
                    className="mt-2 px-4 py-1.5 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
                  >
                    Copy hex to clipboard
                  </button>
                </div>
              </>
            )}

            {!output && !error && (
              <div className="text-gray-400 text-sm p-8 text-center border border-dashed border-gray-300 rounded-lg">
                Configure the ticket parameters and click Generate to see the hex output and Aztec code.
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
