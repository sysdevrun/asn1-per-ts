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

add to the npm library a parser of asn schema notation. the parser must use a npm module for parsing. it outputs a schema that can be used by the asn1-per-ts module. it is unit tested.

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

## Signature verification plan

Plan what would be needed to implement signature verification for intercode6-ts npm module, both for level 1 and level 2 signatures. Cover: extracting signed data bytes via PER re-encoding of sub-structures, OID-to-algorithm mapping, signature format conversion (raw to DER), public key handling (compressed/uncompressed EC points, SPKI wrapping), level 1 external key lookup interface, proposed API design, dependencies (node:crypto vs @noble/curves), edge cases, and testing strategy.

## decodeWithMetadata plan

Add a `decodeWithMetadata` method to every codec that returns a recursive tree of `DecodedNode` objects. Each node wraps the decoded value with metadata: bit position, bit length, raw bytes (Uint8Array), the codec instance that produced it, and schema-level flags (optional, present, default, extension). Store the codec in metadata so `stripMetadata` dispatches on `instanceof` — not by inspecting the value — and throws on unhandled codec types. Add `BitBuffer.extractBits(startBit, bitCount)` returning Uint8Array. Focus on exposing internals and raw field values, not on signature verification.
## Simplify CLAUDE.md

Simplify Claude file: list only directories, update list of directories. Emphasize that the intercode6-ts npm module is the main encoding/decoding library and usually doesn't require understanding low-level primitives in src directory. Examples in examples directory should be enough for most usage.

## Implement decodeWithMetadata

implement DECODE_WITH_METADATA_PLAN.md

update Readme and examples to indicate how the new method works.
add unit tests too

## Update signature verification plan to use decodeWithMetadata

Read last commit. Update plan in intercode6-ts to implement signature with the freshly implemented metadata method.

## Add Aztec code reader to website

In the website, add an Aztec code reader library that allows to browse an image from the phone and decode it and convert it to hex encoded data, so hex encoded can be used as UIC ticket encoded data.

## Publish npm package with GitHub OIDC

Prepare everything needed to publish the asn1-per-ts package as npm module on npm.org with GitHub OIDC connection. Everything must be as easy and automated as possible. Write a PUBLISH.md doc to explain how to proceed. The package will be ESM only, working for both node and browser. Keep website publication on GitHub pages but don't package it in the npm module. Actions should be done via GitHub Actions.

## Rename project from per-unaligned-ts to asn1-per-ts

project has been renamed from per-unaligned-ts to asn1-per-ts.
rename project name everywhere

## Add SNCF TER ticket

in website and in fixtures, add this SNCF TER ticket
01556550004a2000000824687099c04a390100944142a84e4195c6a5264b11d492509158c00814182618330404383a14fb0b5aae64b9cad934a4d30004015038012a8908a9ea09092988a12908a98988a849e9288b172808244005008d08201a0f999b302808410008802144cc44010a268404000c32c350045a0b80080010120000100a0062a30b934b3102737b936b0b6045f62c5c37a751883186a8c4001040400000171816010a3d38d26cd5ef910257206b6e96ffa56d986faf22010a3342b79c99cb27c12f8e412ed4a52f1c347ff32480

## Add Soléa ticket

add this one as Soléa
815565dff8e76000380824687099c04b390101cec142a8864195c6a5264b13249250915fc4040400404080494a6b305cd2fb8c2db1b572cdc2dcd91be45ad1c3164b5c6664c16b072dd8e4c395a32c6d3100014121c1831311931b2b116b2999a32969a32b2b216b09a18b196991c9c19333333189ab1993109500124204006ec90be41900fac0240100607a1a31fe5d80801e103120566f796167652031204865757265000004154324671e81808384154324671e81808384154324671e82018104154324671e8201811081fcaced2780ddfbb1a882f7fc5ca8a452a2dacc95e9abc048beade76918facdde050aa3f895a398228110806017d045a5144200d029ee92860fba45728e8b5cd561375660482b34af855f3401102860f8d89d2f47093220fc20acf2d98c46a82f399aa2495c6f1b4a20ed53942d8246890d88b30279b92ec7a7a79ef87caedbd7668dfd79e5153ff842318220110126f9ec96c791e8580ab939971ba9670bcfb2d40b00941a0dc37cbb97b33bd0a01100a4e94a879c92ff5381fa024759d6d0bb24e6e911455a98ce5ece06aceae7b018

## Add CTS ticket

add this one as CTS
815565dff8e76000380824687099c04fb90101cec142a8944195c6a5264b13249250915fc0048100004080494a6b305ce6fb96edb2b9c2c9aadc9859385ad32b972b5cb964e16e170cb2e4ccd333572c9980014121a9b189a191b1b32169b9a9a9c969a333230969c9931b216b3321c9c9a199a9c9818b21b89500124224806ec929042400590024010064a012321a6102006a00020030010008000350531311548814d2535413114801022214000004154324671e81808384154324671e81808384154324671e82018104154324671e8201811081479ea31897b4f48c0807462750e9fdb93688c1388ba7dd2036ecbf044e226cb9050aa43095a4182301108044ba579cec8a293c2d908fa4f6171b181595b9f61dccfae6dd2f8dfae4f3e5b90110807a3419bd5b3be394d21db00e46f98f864e4c91df2b88d673904a1e0fccd951a58246890d88c302b9b92ec7d39aee7d3961e78b7f5e59d775cfbc55017602398228110153cf8041bb028f8107570846874ca818a6560ce262c0124df25a987611286658110805006c02f828f7e689858bdbb5f884b4db1376813211fb01269a22375748b47d18

## Update SIGNATURE_VERIFICATION_PLAN.md

update file intercode6-ts/SIGNATURE_VERIFICATION_PLAN.md

explore https://railpublickey.uic.org/download.php and add a section to explain how to fetch and find level 1 public key.

remove "Why This Is Better Than Re-encoding" section

keys can be stored in two ways:

[91 bytes] 3059301306072a8648ce3d020106082a8648ce3d0301070342000404e3c5db6ad27110dde489f99037edcad2f594345cd4b3c354fdc87967c4c8ca2a3e559ef3b26258c6531345ab8904704f35a3802318fc8cd1782f4e198da9c9

[33 bytes] 028f3d46312f69e918100e8c4ea1d3fb726d118271174fba406dd97e089c44d972

update text to give examples and tell conversion may be needed depending of the crypto library

add the requirement the intercode6-ts module must be usable on both browser and node

## Add signature fixtures and correct signature format

find Soléa CTS and TER SNCF ticket in fixtures. indicate the path in the guide. tell to run unit tests against those tickets and verify the signatures. extract the related signatures into a fixtures committed to the project

examples of signatures
Level 1 signature:
[46 bytes] 302c02147a71a4d9abdf2204ae40d6dd2dff4adb30df5e44021466856f3933964f825f1c825da94a5e3868ffe649

Level 2 signature:
[70 bytes] 3044022024df3d92d8f23d0b01572732e3752ce179f65a8160128341b86f9772f6677a140220149d2950f3925fea703f4048eb3ada17649cdd2228ab5319cbd9c0d59d5cf603

Level 1 signature:
[71 bytes] 3045022100c02fa08b4a288401a053dd250c1f748ae51d16b9aac26eacc09056695f0abe68022050c1f1b13a5e8e126441f84159e5b3188d505e73354492b8de369441daa7285b

Level 2 signature:
[71 bytes] 304502202a79f008376051f020eae108d0e9950314cac19c4c580249be4b530ec2250ccb022100a00d805f051efcd130b17b76bf10969b626ed026423f6024d34446eae9168fa3

Level 1 signature:
[72 bytes] 30460221008974af39d91452785b211f49ec2e36302b2b73ec3b99f5cdba5f1bf5c9e7cb72022100f468337ab677c729a43b601c8df31f0c9c9923be5711ace720943c1f99b2a34b

## Evaluate Zod for ASN.1 schema to typed TypeScript objects

Evaluate how Zod could be used to output TypeScript typed objects depending on the ASN JSON schema. Test options on basic types and SEQUENCE. Write a plan.

## Remove UIC/Intercode from website

In website, remove everything related to UIC or intercode. Keep only focus on ASN.1 PER unaligned encoding decoding. Also update README if needed and any reference to it. Add link to https://github.com/sysdevrun/dosipas-ts as sister project using the library.
