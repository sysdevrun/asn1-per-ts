export default function ProjectDescription() {
  return (
    <section>
      <h2 className="text-xl font-semibold mb-4">About</h2>
      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4 text-sm leading-relaxed text-gray-700">
        <p>
          <strong>asn1-per-ts</strong> is a TypeScript library for encoding
          and decoding data using ASN.1 PER (Packed Encoding Rules) unaligned
          variant, as defined in ITU-T X.691.
        </p>
        <p>
          PER unaligned encoding produces the most compact binary
          representation of structured data by encoding values at the bit level
          without any padding between fields. This makes it ideal for
          bandwidth-constrained protocols in telecommunications, aviation, and
          IoT.
        </p>

        <h3 className="font-semibold text-gray-900 pt-2">Supported Types</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {[
            ['BOOLEAN', 'Single bit (0/1)'],
            ['INTEGER', 'Constrained, semi-constrained, or unconstrained'],
            ['ENUMERATED', 'Indexed enumeration values'],
            ['BIT STRING', 'Arbitrary bit sequences'],
            ['OCTET STRING', 'Byte sequences'],
            ['IA5String', 'ASCII character strings'],
            ['VisibleString', 'Printable character strings'],
            ['UTF8String', 'UTF-8 encoded strings'],
            ['NULL', 'Zero-bit placeholder'],
            ['CHOICE', 'Tagged union of alternatives'],
            ['SEQUENCE', 'Ordered collection of fields'],
            ['SEQUENCE OF', 'Homogeneous list'],
          ].map(([name, desc]) => (
            <div key={name} className="bg-gray-50 rounded px-3 py-2">
              <code className="text-xs font-semibold text-indigo-700">{name}</code>
              <p className="text-xs text-gray-500 mt-0.5">{desc}</p>
            </div>
          ))}
        </div>

        <h3 className="font-semibold text-gray-900 pt-2">Features</h3>
        <ul className="list-disc list-inside space-y-1">
          <li>Bit-level buffer with MSB-first encoding</li>
          <li>Constraint-based encoding (size, value range, extensibility)</li>
          <li>Schema-driven JSON encoding and decoding</li>
          <li>Default value support in SEQUENCE fields</li>
          <li>Extension marker support for forward compatibility</li>
          <li>ASN.1 text notation parser (paste .asn files directly)</li>
        </ul>

        <h3 className="font-semibold text-gray-900 pt-2">Sister Project</h3>
        <p>
          <a
            href="https://github.com/sysdevrun/dosipas-ts"
            target="_blank"
            rel="noopener noreferrer"
            className="text-indigo-600 hover:underline font-medium"
          >
            dosipas-ts
          </a>{' '}
          &mdash; a TypeScript library built on top of asn1-per-ts for encoding and decoding
          DOSIPAS / ERA electronic ticket data.
        </p>
      </div>
    </section>
  );
}
