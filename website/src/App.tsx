import { useState } from 'react';
import Header from './components/Header';
import ProjectDescription from './components/ProjectDescription';
import SchemaBuilder from './components/SchemaBuilder';
import EncoderDecoder from './components/EncoderDecoder';
import AsnSchemaParser from './components/AsnSchemaParser';
import Footer from './components/Footer';
import type { SchemaNode } from 'asn1-per-ts';

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

export default function App() {
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

        <section>
          <h2 className="text-xl font-semibold mb-4">ASN.1 Schema Parser</h2>
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <AsnSchemaParser onSchemaSelect={handleSchemaChange} />
          </div>
        </section>

        <SchemaBuilder
          schemaText={schemaText}
          schemaError={schemaError}
          onChange={handleSchemaChange}
        />

        <EncoderDecoder schema={schema} schemaError={schemaError} />
      </main>
      <Footer />
    </div>
  );
}
