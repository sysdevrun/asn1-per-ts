# UIC Barcode Schemas

Pre-generated PER unaligned `SchemaNode` definitions for the UIC (Union Internationale des Chemins de fer) railway barcode standards.

These schemas were generated from the official ASN.1 sources using `parseAsn1Module()` and `convertModuleToSchemaNodes()`.

## Schemas

| Schema | ASN.1 Source | Description |
|--------|-------------|-------------|
| [uicBarcodeHeader.schema.json](./uicBarcodeHeader.schema.json) | [uicBarcodeHeader_v2.0.1.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicBarcodeHeader_v2.0.1.asn) | UIC barcode header with multi-level signature support (v2.0.1) |
| [uicRailTicketData.schema.json](./uicRailTicketData.schema.json) | [uicRailTicketData_v3.0.5.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v3.0.5.asn) | UIC rail ticket data with all document types (v3.0.5) |

## Usage

```typescript
import { SchemaBuilder, SchemaCodec } from 'per-unaligned-ts';
import headerSchemas from './uicBarcodeHeader.schema.json';
import ticketSchemas from './uicRailTicketData.schema.json';

// Build a codec for the barcode header
const headerCodec = new SchemaCodec(headerSchemas.UicBarcodeHeader);

// For the rail ticket data (contains recursive $ref types),
// use SchemaBuilder.buildAll() to resolve references:
const ticketCodecs = SchemaBuilder.buildAll(ticketSchemas);
const ticketCodec = ticketCodecs['UicRailTicketData'];
```

## Notes

- The rail ticket data schema contains recursive type references (`ViaStationType` references itself). These are represented as `{ "type": "$ref", "ref": "ViaStationType" }` nodes in the JSON. Use `SchemaBuilder.buildAll()` to resolve them.
- Type references are inlined during conversion, so each schema file is self-contained.
