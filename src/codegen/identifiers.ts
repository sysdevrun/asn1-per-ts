/**
 * ASN.1 identifiers allow hyphens (`Uic-RailTicketData`, `issuing-detail`),
 * which TypeScript does not. Type names are rewritten; property names are kept
 * verbatim and quoted where necessary, so the generated types still match the
 * decoded objects key for key.
 */

/**
 * Names a generated type must not take.
 *
 * TypeScript's own keywords are all lowercase and cannot survive PascalCasing,
 * so the real hazards are the global types the generated code relies on and
 * the identifiers the generated file imports for itself — a type named
 * `TypedCodec` would shadow the import and break the file.
 */
const RESERVED = new Set([
  // Globals the emitted types reference or that would be confusing to shadow.
  'Array', 'BigInt', 'Boolean', 'Date', 'Error', 'Function', 'Map', 'Number', 'Object',
  'Promise', 'RegExp', 'Set', 'String', 'Symbol', 'Uint8Array',
  // Identifiers the generated module imports.
  'BitStringValue', 'SchemaRegistry', 'TypedCodec', 'createCodecs',
]);

const VALID_PROPERTY = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** Whether a decoded object key can be written unquoted in an interface. */
export function isValidPropertyName(name: string): boolean {
  return VALID_PROPERTY.test(name);
}

/** Render an object key, quoting it when it is not a bare identifier. */
export function propertyKey(name: string): string {
  return isValidPropertyName(name) ? name : JSON.stringify(name);
}

/** Turn an ASN.1 type name into a PascalCase TypeScript identifier. */
export function toTypeName(asnName: string): string {
  const pascal = asnName
    .replace(/[^A-Za-z0-9]+(.)?/g, (_match, next: string | undefined) =>
      next ? next.toUpperCase() : '',
    )
    .replace(/^[a-z]/, first => first.toUpperCase());
  const cleaned = pascal.replace(/^[^A-Za-z_$]+/, '');
  if (cleaned === '') return 'Type';
  return RESERVED.has(cleaned) ? `${cleaned}_` : cleaned;
}

/**
 * Map every ASN.1 type name to a unique TypeScript identifier.
 *
 * Both `Foo-Bar` and `FooBar` sanitize to `FooBar`, and the generated `Input`
 * aliases share the same namespace, so collisions are resolved by numbering.
 */
export function buildNameMap(asnNames: readonly string[], reserved: readonly string[] = []): Map<string, string> {
  const taken = new Set<string>(reserved);
  const map = new Map<string, string>();
  for (const asnName of asnNames) {
    const base = toTypeName(asnName);
    let candidate = base;
    let n = 2;
    while (taken.has(candidate) || taken.has(`${candidate}Input`)) {
      candidate = `${base}${n++}`;
    }
    taken.add(candidate);
    taken.add(`${candidate}Input`);
    map.set(asnName, candidate);
  }
  return map;
}
