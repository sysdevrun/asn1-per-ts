# PROMPT

## Initial prompt

plan a typescript npm module project used to decode and encode per unaligned data.
it has primitives to manage a buffer at the bit level and encode and decode very common types such as Boolean, u5 string, numbers, enum , etc.
when configuring the encoders or decoders, they accept constraints and default values so it correctly encodes or decodes based on constraints and value to be encoded.
every class is unit tested.

a more high level part allows to configure a schema of combination of primitive types and allows to encode a JSON object (if object does not match the schema an exception is raised). when decoding an array buffer, a JSON object is returned.

in the GitHub repository, add a react typescript tailwindcss website that will be published on the GitHub pages with ./ assets path. it describe the project, allows to configure a schema and either decode a hex encoded data or encode a JSON object. When building the website, it uses the npm module of the project

## ASN.1 Schema Parser

analyze how to create a schema that can be used to encode or decode a document.

fetch https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicBarcodeHeader_v2.0.1.asn

add to the npm library a parser of asn schema notation. the parser must use a npm module for parsing. it outputs a schema that can be used by the per-unaligned-ts module. it is unit tested.

the parser is run against the UIC schema to verify it works.
if some constraints are not implemented yet, they are described in a TODO.md file.

this prompt is added to the PROMPT.md file in a new section.
in Claude md file, a statement is added to tell Claude to add the prompt file each time a prompt is given to edit the project.

## Website ASN.1 Parser UI

on the website, add an interface to use the schema parser. the output schema can then be used to encode or decode.

## Fix CLAUDE.md prompt history instruction

you added

# Prompt history

When editing this project, always read `PROMPT.md` first to understand the history of prompts and design decisions that shaped the codebase

the goal is to append on every prompt the file so it's possible to get all the prompts used to generate the project.
also add the two prompts of this conversation

## Fix GitHub Pages deploy: missing peggy dependency

deploy to GitHub pages fail with
Cannot find module 'peggy' or its corresponding type declarations.

## Encode schema documents

use the library to encode the following schema:
id : integer with default value 5
name: ia5string default value hello

then encode the two documents
id: 5, name: hello
id: 42, name world

## Test for decoding

test for decoding

## Schema versioning with extension marker

new schemas:
schema v1
id : integer
extension marker enabled

schema v2
id : integer
extension marker
name: ia5string

objects to encode in round trip:
id :42 , With v1 and v2
id: 100, name: world, with v2. decode with v1 the output got from encoding from v2 too

## Extension marker position

does the position of the extension marker matter

## Extension marker documentation and parser fix

add clearly in the documentation how to indicate the marker extension is present.

in the asn schema parser, ensure this is correctly added in the schema.
add specific unit tests for that

## End-to-end ASN.1 tests

add a test section dedicated to full end to end tests.
add the conversions with ASN parser and encoding and decoding for real-world ASN.1 types from the Intercode specification (IntercodeIssuingData, ProductRetailerData, RetailChannelData, IntercodeDynamicData) and the UIC Barcode Header standard. Expected PER unaligned encoding hex values are verified against the specification documents.

## OBJECT IDENTIFIER codec implementation

Implement native OBJECT IDENTIFIER support for PER encoding/decoding. Create ObjectIdentifierCodec that encodes/decodes OID dot-notation strings using BER contents octets (X.690 §8.19) wrapped in PER unconstrained length determinant (X.691 §23). Add OBJECT IDENTIFIER to SchemaNode union and SchemaBuilder. Change default objectIdentifierHandling from 'error' to 'native'. Add end-to-end ASN.1 parse/encode/decode roundtrip tests including SEQUENCE with optional OID fields, CHOICE with OID alternatives, SEQUENCE OF OID, and the UIC barcode schema with all 4 OID fields.

## Generate UIC barcode ASN.1 schemas

Download both UIC barcode ASN.1 files (uicBarcodeHeader_v2.0.1.asn and uicRailTicketData_v3.0.5.asn) and generate SchemaNode JSON schemas using the ASN.1 parser. Create a dedicated `schemas/uic-barcode/` directory to save the resulting schemas. Add a README in this directory with links to each original ASN.1 source. Add a link to this README in the main README. Do not save or commit the ASN.1 source files.

## Recursive schema unit tests

Create specific unit tests in both the ASN.1 parser/converter and the encoder to check recursive schemas are supported. For the encoder, write at least a document that has 3 deep levels of recursivity, encode and decode it to check it works as expected.

## Generate Intercode schemas

Compile the Intercode ASN.1 types (IntercodeIssuingData, ProductRetailerData, RetailChannelData, IntercodeDynamicData) and save the schema as intercode6.schema.json next to the UIC barcode schemas.

## UIC barcode header fixture test

In tests fixtures, add uicbarcodeheader example of hex data. In e2e test directory, add new test that decodes the fixture using compiled schemas in schemas directory.
## Regenerate UIC schemas with CLI tool

Refetch the UIC ASN.1 schemas from GitHub and regenerate the SchemaNode JSON files. Create a reusable CLI tool in `cli/generate-schema.ts` that reads a local `.asn` file and outputs the corresponding `.schema.json`.

## Decode UIC barcode with Intercode 6 extensions

Download uicRailTicketData_v2.0.3.asn from https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/blob/master/misc/uicRailTicketData_v2.0.3.asn and encode it to JSON schema with the CLI tool. Add it to the schemas directory and update the README. In cli directory, add a TypeScript program that decodes the UIC barcode header fixture (v1) and outputs the details of the ticket. Dispatch on dataFormat to decode FCB2 data as UicRailTicketData using the v2 schema. Dispatch on extensionId pattern "_<RICS>II1" to decode extensionData as IntercodeIssuingData. Dispatch on dataFormat pattern "_<RICS>.ID1" to decode level2Data as IntercodeDynamicData.

## Update schema versions

For each schema file already present in the schemas directory, fetch the latest minor version of every major version of that schema type from https://github.com/UnionInternationalCheminsdeFer/UIC-barcode/tree/master/misc. Convert the ASN.1 source using the CLI tool and save the resulting schema JSON. Update the schemas README to reference the new files and add a Version column with the full version number.

## Add examples documentation

Create a new examples/ directory with a schema parser markdown file with examples of usage and explanation of options. Do the same thing for decoding binary data encoded with PER unaligned. Do the same thing for encoding object to binary. Use files in CLI and the classes referenced to find usage. Reference every file in the README and CLAUDE files.

## Intercode 6 decoder/generator module

Read the CLI for decoding intercode6 tickets. Create in an intercode6-ts directory a npm module (for both web and node) that decodes binary encoded data. When the module is compiled, the JSON schemas must be embedded in the module. Create TypeScript types for the result. Also create an encoding method. In the website, add a new tab that allows to decode a ticket from hex encoded data showing every detail. Add as example the current fixture. Add a new tab that generates a ticket to hex encoded plus Aztec code. The intercode6-ts module must be added to the website.

## Simplify CLAUDE.md

Simplify Claude file: list only directories, update list of directories. Emphasize that the intercode6-ts npm module is the main encoding/decoding library and usually doesn't require understanding low-level primitives in src directory. Examples in examples directory should be enough for most usage.
