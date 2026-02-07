interface SchemaBuilderProps {
  schemaText: string;
  schemaError: string | null;
  onChange: (text: string) => void;
}

const EXAMPLE_SCHEMAS = [
  {
    label: 'Simple Message',
    schema: {
      type: 'SEQUENCE',
      fields: [
        { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
        { name: 'active', schema: { type: 'BOOLEAN' } },
        {
          name: 'status',
          schema: { type: 'ENUMERATED', values: ['pending', 'approved', 'rejected'] },
        },
      ],
    },
  },
  {
    label: 'Protocol Packet',
    schema: {
      type: 'SEQUENCE',
      fields: [
        {
          name: 'messageType',
          schema: { type: 'ENUMERATED', values: ['request', 'response', 'notification'] },
        },
        { name: 'sequenceNumber', schema: { type: 'INTEGER', min: 0, max: 65535 } },
        {
          name: 'payload',
          schema: {
            type: 'CHOICE',
            alternatives: [
              { name: 'text', schema: { type: 'VisibleString', minSize: 0, maxSize: 100 } },
              { name: 'data', schema: { type: 'OCTET STRING', minSize: 0, maxSize: 256 } },
            ],
          },
        },
        { name: 'priority', schema: { type: 'INTEGER', min: 1, max: 10 }, optional: true },
      ],
    },
  },
  {
    label: 'List of Records',
    schema: {
      type: 'SEQUENCE OF',
      item: {
        type: 'SEQUENCE',
        fields: [
          { name: 'name', schema: { type: 'VisibleString', alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ', minSize: 1, maxSize: 20 } },
          { name: 'score', schema: { type: 'INTEGER', min: 0, max: 100 } },
        ],
      },
      minSize: 0,
      maxSize: 50,
    },
  },
  {
    label: 'Boolean',
    schema: { type: 'BOOLEAN' },
  },
  {
    label: 'Constrained Integer',
    schema: { type: 'INTEGER', min: 0, max: 255 },
  },
];

export default function SchemaBuilder({ schemaText, schemaError, onChange }: SchemaBuilderProps) {
  return (
    <section>
      <h2 className="text-xl font-semibold mb-4">Schema Definition</h2>
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex flex-wrap gap-2 mb-4">
          {EXAMPLE_SCHEMAS.map((ex) => (
            <button
              key={ex.label}
              onClick={() => onChange(JSON.stringify(ex.schema, null, 2))}
              className="text-xs px-3 py-1.5 bg-indigo-50 text-indigo-700 rounded hover:bg-indigo-100 transition-colors border border-indigo-200"
            >
              {ex.label}
            </button>
          ))}
        </div>
        <p className="text-xs text-gray-500 mb-2">
          Define your ASN.1 type schema as JSON. Use the examples above as templates.
        </p>
        <textarea
          value={schemaText}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          className={`w-full h-64 font-mono text-sm p-4 border rounded-lg resize-y focus:outline-none focus:ring-2 ${
            schemaError
              ? 'border-red-300 focus:ring-red-300 bg-red-50'
              : 'border-gray-300 focus:ring-indigo-300 bg-gray-50'
          }`}
        />
        {schemaError && (
          <p className="text-red-600 text-xs mt-2">Schema error: {schemaError}</p>
        )}
      </div>
    </section>
  );
}
