export default function Footer() {
  return (
    <footer className="bg-gray-100 border-t border-gray-200 mt-10">
      <div className="max-w-6xl mx-auto px-4 py-4 text-center text-xs text-gray-500">
        <p>
          per-unaligned-ts &mdash; ASN.1 PER unaligned encoding in TypeScript.{' '}
          <a
            href="https://github.com/sysdevrun/per-unaligned-ts"
            target="_blank"
            rel="noopener noreferrer"
            className="text-indigo-600 hover:underline"
          >
            Source on GitHub
          </a>
        </p>
      </div>
    </footer>
  );
}
