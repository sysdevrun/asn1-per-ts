# UIC Barcode Schemas

Pre-generated PER unaligned `SchemaNode` definitions for the UIC (Union Internationale des Chemins de fer) railway barcode standards.

These schemas were generated from the official ASN.1 sources using `parseAsn1Module()` and `convertModuleToSchemaNodes()`.

## Schemas

| Schema | Version | ASN.1 Source | Description |
|--------|---------|-------------|-------------|
| [uicBarcodeHeader_v1.schema.json](./uicBarcodeHeader_v1.schema.json) | 1.0.0 | [uicBarcodeHeader_v1.0.0.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicBarcodeHeader_v1.0.0.asn) | UIC barcode header v1 — basic multi-level signature structure without validity period fields |
| [uicBarcodeHeader_v2.schema.json](./uicBarcodeHeader_v2.schema.json) | 2.0.1 | [uicBarcodeHeader_v2.0.1.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicBarcodeHeader_v2.0.1.asn) | UIC barcode header v2 — adds `endOfValidityYear`, `endOfValidityDay`, `endOfValidityTime`, and `validityDuration` fields to `Level1DataType` |
| [uicRailTicketData_v1.schema.json](./uicRailTicketData_v1.schema.json) | 1.3.5 | [uicRailTicketData_v1.3.5.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v1.3.5.asn) | UIC rail ticket data v1 — used by FCB1 barcode format |
| [uicRailTicketData_v2.schema.json](./uicRailTicketData_v2.schema.json) | 2.0.3 | [uicRailTicketData_v2.0.3.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v2.0.3.asn) | UIC rail ticket data v2 — used by FCB2 barcode format |
| [uicRailTicketData_v3.schema.json](./uicRailTicketData_v3.schema.json) | 3.0.5 | [uicRailTicketData_v3.0.5.asn](https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v3.0.5.asn) | UIC rail ticket data v3 — all document types |
| [intercode6.schema.json](./intercode6.schema.json) | 6 | Intercode XP P 99-405-6 | Intercode issuing data, retail channel, product retailer, and dynamic content |

## Usage

```typescript
import { SchemaBuilder, SchemaCodec } from 'asn1-per-ts';
import headerSchemas from './uicBarcodeHeader_v2.schema.json';
import ticketSchemas from './uicRailTicketData_v3.schema.json';

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
