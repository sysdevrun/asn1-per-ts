import { useState } from 'react';
import { parseAsn1Module, convertModuleToSchemaNodes } from 'asn1-per-ts';
import type { SchemaNode } from 'asn1-per-ts';

interface AsnSchemaParserProps {
  onSchemaSelect: (schemaText: string) => void;
}

const SIMPLE_EXAMPLE = `SimpleProtocol DEFINITIONS AUTOMATIC TAGS ::= BEGIN

Message ::= SEQUENCE {
    id INTEGER (0..255),
    active BOOLEAN,
    status Status
}

Status ::= ENUMERATED { pending, approved, rejected }

END`;

const CHOICE_EXAMPLE = `ChoiceDemo DEFINITIONS AUTOMATIC TAGS ::= BEGIN

Packet ::= SEQUENCE {
    tag INTEGER (0..15),
    payload Payload
}

Payload ::= CHOICE {
    text IA5String,
    number INTEGER (0..65535),
    flag BOOLEAN
}

END`;

const EXTENSION_EXAMPLE = `ExtensionDemo DEFINITIONS AUTOMATIC TAGS ::= BEGIN

MessageV2 ::= SEQUENCE {
    id INTEGER (0..255),
    name IA5String,
    ...,
    email IA5String
}

Color ::= ENUMERATED { red, green, blue, ..., yellow, purple }

END`;

const EXAMPLES = [
  { label: 'Simple Protocol', text: SIMPLE_EXAMPLE },
  { label: 'Choice Demo', text: CHOICE_EXAMPLE },
  { label: 'Extension Markers', text: EXTENSION_EXAMPLE },
];

export default function AsnSchemaParser({ onSchemaSelect }: AsnSchemaParserProps) {
  const [asnText, setAsnText] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [typeNames, setTypeNames] = useState<string[]>([]);
  const [schemas, setSchemas] = useState<Record<string, SchemaNode>>({});
  const [selectedType, setSelectedType] = useState<string | null>(null);

  const handleParse = (text?: string) => {
    const input = text ?? asnText;
    setParseError(null);
    setTypeNames([]);
    setSchemas({});
    setSelectedType(null);

    if (!input.trim()) {
      setParseError('Enter ASN.1 notation to parse');
      return;
    }

    try {
      const module = parseAsn1Module(input);
      const converted = convertModuleToSchemaNodes(module);
      const names = Object.keys(converted);
      if (names.length === 0) {
        setParseError('No type assignments found in module');
        return;
      }
      setSchemas(converted);
      setTypeNames(names);
      setSelectedType(names[0]);
    } catch (e: unknown) {
      setParseError(e instanceof Error ? e.message : 'Parse failed');
    }
  };

  const handleUseSchema = () => {
    if (selectedType && schemas[selectedType]) {
      onSchemaSelect(JSON.stringify(schemas[selectedType], null, 2));
    }
  };

  const handleExampleClick = (text: string) => {
    setAsnText(text);
    handleParse(text);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            onClick={() => handleExampleClick(ex.text)}
            className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
          >
            {ex.label}
          </button>
        ))}
      </div>

      <p className="text-xs text-gray-500">
        Paste ASN.1 module notation below. Supports SEQUENCE, SEQUENCE OF, CHOICE, ENUMERATED,
        INTEGER with constraints, OBJECT IDENTIFIER, string types, OPTIONAL, and type references.
      </p>

      <textarea
        value={asnText}
        onChange={(e) => setAsnText(e.target.value)}
        spellCheck={false}
        className={`w-full h-64 font-mono text-sm p-4 border rounded-lg resize-y focus:outline-none focus:ring-2 ${
          parseError
            ? 'border-red-300 focus:ring-red-300 bg-red-50'
            : 'border-gray-300 focus:ring-indigo-300 bg-gray-50'
        }`}
        placeholder={`MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN\n\n  MyType ::= SEQUENCE {\n    id INTEGER (0..255),\n    name IA5String\n  }\n\nEND`}
      />

      <button
        onClick={() => handleParse()}
        className="px-5 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors"
      >
        Parse Module
      </button>

      {parseError && (
        <p className="text-red-600 text-xs">{parseError}</p>
      )}

      {typeNames.length > 0 && (
        <div className="border border-gray-200 rounded-lg p-4 bg-gray-50 space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-sm font-medium text-gray-700">Select type:</label>
            <div className="flex flex-wrap gap-2">
              {typeNames.map((name) => (
                <button
                  key={name}
                  onClick={() => setSelectedType(name)}
                  className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                    selectedType === name
                      ? 'bg-indigo-600 text-white border-indigo-600'
                      : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-100'
                  }`}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>

          {selectedType && schemas[selectedType] && (
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">
                Generated SchemaNode for {selectedType}:
              </label>
              <pre className="text-xs font-mono bg-white border border-gray-200 rounded p-3 overflow-auto max-h-48 text-gray-700">
                {JSON.stringify(schemas[selectedType], null, 2)}
              </pre>
            </div>
          )}

          <button
            onClick={handleUseSchema}
            disabled={!selectedType}
            className="px-5 py-2 bg-green-600 text-white text-sm rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Use "{selectedType}" for Encode / Decode
          </button>
        </div>
      )}
    </div>
  );
}
