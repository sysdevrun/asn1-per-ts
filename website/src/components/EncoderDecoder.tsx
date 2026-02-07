import { useState } from 'react';
import { SchemaCodec } from 'per-unaligned-ts';
import type { SchemaNode } from 'per-unaligned-ts';

interface EncoderDecoderProps {
  schema: SchemaNode;
  schemaError: string | null;
}

export default function EncoderDecoder({ schema, schemaError }: EncoderDecoderProps) {
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [jsonInput, setJsonInput] = useState('{\n  "id": 42,\n  "active": true,\n  "status": "approved"\n}');
  const [hexInput, setHexInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleEncode = () => {
    if (schemaError) {
      setError('Fix the schema errors first');
      return;
    }
    try {
      const codec = new SchemaCodec(schema);
      const value = JSON.parse(jsonInput, (_key, val) => {
        // Convert arrays that look like Uint8Arrays back
        if (val && typeof val === 'object' && val.type === 'Buffer' && Array.isArray(val.data)) {
          return new Uint8Array(val.data);
        }
        return val;
      });
      const hex = codec.encodeToHex(value);
      setOutput(hex);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Encoding failed');
      setOutput('');
    }
  };

  const handleDecode = () => {
    if (schemaError) {
      setError('Fix the schema errors first');
      return;
    }
    try {
      const cleanHex = hexInput.replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
        throw new Error('Invalid hex characters');
      }
      if (cleanHex.length === 0) {
        throw new Error('Hex input is empty');
      }
      if (cleanHex.length % 2 !== 0) {
        throw new Error('Hex string must have even number of characters');
      }
      const codec = new SchemaCodec(schema);
      const result = codec.decodeFromHex(cleanHex);
      setOutput(JSON.stringify(result, (_key, val) => {
        if (val instanceof Uint8Array) {
          return Array.from(val).map(b => b.toString(16).padStart(2, '0')).join(' ');
        }
        return val;
      }, 2));
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Decoding failed');
      setOutput('');
    }
  };

  return (
    <section>
      <h2 className="text-xl font-semibold mb-4">Encode / Decode</h2>
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setMode('encode')}
            className={`px-4 py-2 text-sm rounded-lg transition-colors ${
              mode === 'encode'
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Encode JSON to Hex
          </button>
          <button
            onClick={() => setMode('decode')}
            className={`px-4 py-2 text-sm rounded-lg transition-colors ${
              mode === 'decode'
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Decode Hex to JSON
          </button>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              {mode === 'encode' ? 'JSON Input' : 'Hex Input'}
            </label>
            {mode === 'encode' ? (
              <textarea
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                spellCheck={false}
                className="w-full h-48 font-mono text-sm p-4 border border-gray-300 rounded-lg resize-y bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-300"
                placeholder='{"id": 42, "active": true}'
              />
            ) : (
              <textarea
                value={hexInput}
                onChange={(e) => setHexInput(e.target.value)}
                spellCheck={false}
                className="w-full h-48 font-mono text-sm p-4 border border-gray-300 rounded-lg resize-y bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-300"
                placeholder="2ab4e0..."
              />
            )}
            <button
              onClick={mode === 'encode' ? handleEncode : handleDecode}
              disabled={!!schemaError}
              className="mt-3 px-5 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {mode === 'encode' ? 'Encode' : 'Decode'}
            </button>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              {mode === 'encode' ? 'Hex Output' : 'JSON Output'}
            </label>
            <div className="w-full h-48 font-mono text-sm p-4 border border-gray-300 rounded-lg bg-gray-50 overflow-auto whitespace-pre-wrap break-all">
              {error ? (
                <span className="text-red-600">{error}</span>
              ) : output ? (
                output
              ) : (
                <span className="text-gray-400">
                  {mode === 'encode' ? 'Encoded hex will appear here' : 'Decoded JSON will appear here'}
                </span>
              )}
            </div>
            {output && !error && (
              <button
                onClick={() => navigator.clipboard.writeText(output)}
                className="mt-3 px-4 py-1.5 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
              >
                Copy to clipboard
              </button>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
