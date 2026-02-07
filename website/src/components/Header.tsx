export default function Header() {
  return (
    <header className="bg-gray-900 text-white">
      <div className="max-w-6xl mx-auto px-4 py-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">per-unaligned-ts</h1>
          <p className="text-gray-400 text-sm mt-1">
            PER (Packed Encoding Rules) unaligned encoder/decoder for ASN.1 types
          </p>
        </div>
        <a
          href="https://github.com/sysdevrun/per-unaligned-ts"
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-400 hover:text-white transition-colors text-sm border border-gray-700 px-3 py-1.5 rounded"
        >
          GitHub
        </a>
      </div>
    </header>
  );
}
