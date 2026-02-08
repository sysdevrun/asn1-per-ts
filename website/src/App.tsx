import { useState } from 'react';
import Header from './components/Header';
import ProjectDescription from './components/ProjectDescription';
import SchemaBuilder from './components/SchemaBuilder';
import EncoderDecoder from './components/EncoderDecoder';
import Intercode6Decoder from './components/Intercode6Decoder';
import Intercode6Generator from './components/Intercode6Generator';
import Footer from './components/Footer';
import type { SchemaNode } from 'per-unaligned-ts';

type Tab = 'per' | 'ic6-decode' | 'ic6-generate';

const DEFAULT_SCHEMA: SchemaNode = {
  type: 'SEQUENCE',
  fields: [
    { name: 'id', schema: { type: 'INTEGER', min: 0, max: 255 } },
    { name: 'active', schema: { type: 'BOOLEAN' } },
    {
      name: 'status',
      schema: { type: 'ENUMERATED', values: ['pending', 'approved', 'rejected'] },
    },
  ],
};

const TABS: { key: Tab; label: string }[] = [
  { key: 'per', label: 'PER Encode / Decode' },
  { key: 'ic6-decode', label: 'Intercode 6 Decoder' },
  { key: 'ic6-generate', label: 'Intercode 6 Generator' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('per');
  const [schema, setSchema] = useState<SchemaNode>(DEFAULT_SCHEMA);
  const [schemaText, setSchemaText] = useState(JSON.stringify(DEFAULT_SCHEMA, null, 2));
  const [schemaError, setSchemaError] = useState<string | null>(null);

  const handleSchemaChange = (text: string) => {
    setSchemaText(text);
    try {
      const parsed = JSON.parse(text) as SchemaNode;
      setSchema(parsed);
      setSchemaError(null);
    } catch (e: unknown) {
      setSchemaError(e instanceof Error ? e.message : 'Invalid JSON');
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1 max-w-6xl mx-auto w-full px-4 py-8 space-y-8">
        <ProjectDescription />

        {/* Tab navigation */}
        <div className="border-b border-gray-200">
          <nav className="flex gap-1 -mb-px">
            {TABS.map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors ${
                  tab === key
                    ? 'bg-white border border-gray-200 border-b-white text-indigo-600 -mb-px'
                    : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab content */}
        {tab === 'per' && (
          <div className="space-y-10">
            <SchemaBuilder
              schemaText={schemaText}
              schemaError={schemaError}
              onChange={handleSchemaChange}
            />
            <EncoderDecoder schema={schema} schemaError={schemaError} />
          </div>
        )}

        {tab === 'ic6-decode' && <Intercode6Decoder />}

        {tab === 'ic6-generate' && <Intercode6Generator />}
      </main>
      <Footer />
    </div>
  );
}
