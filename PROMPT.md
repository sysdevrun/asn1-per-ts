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
