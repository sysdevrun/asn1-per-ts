import { parseAsn1Module } from '../../src/parser/AsnParser';
import { convertModuleToSchemaNodes } from '../../src/parser/toSchemaNode';
import type { SchemaNode } from '../../src/schema/SchemaBuilder';
import { SchemaBuilder } from '../../src/schema/SchemaBuilder';

function convertSingle(typeDef: string): SchemaNode {
  const mod = parseAsn1Module(
    `Test DEFINITIONS ::= BEGIN\n  TestType ::= ${typeDef}\nEND`,
  );
  const schemas = convertModuleToSchemaNodes(mod);
  return schemas['TestType'];
}

describe('convertModuleToSchemaNodes', () => {
  describe('primitive types', () => {
    it('converts BOOLEAN', () => {
      expect(convertSingle('BOOLEAN')).toEqual({ type: 'BOOLEAN' });
    });

    it('converts NULL', () => {
      expect(convertSingle('NULL')).toEqual({ type: 'NULL' });
    });

    it('converts INTEGER', () => {
      expect(convertSingle('INTEGER')).toEqual({ type: 'INTEGER' });
    });

    it('converts BIT STRING', () => {
      expect(convertSingle('BIT STRING')).toEqual({ type: 'BIT STRING' });
    });

    it('converts OCTET STRING', () => {
      expect(convertSingle('OCTET STRING')).toEqual({ type: 'OCTET STRING' });
    });

    it('converts IA5String', () => {
      expect(convertSingle('IA5String')).toEqual({ type: 'IA5String' });
    });

    it('converts VisibleString', () => {
      expect(convertSingle('VisibleString')).toEqual({ type: 'VisibleString' });
    });

    it('converts UTF8String', () => {
      expect(convertSingle('UTF8String')).toEqual({ type: 'UTF8String' });
    });

    it('converts OBJECT IDENTIFIER', () => {
      expect(convertSingle('OBJECT IDENTIFIER')).toEqual({ type: 'OBJECT IDENTIFIER' });
    });
  });

  describe('constrained types', () => {
    it('converts INTEGER with value constraint', () => {
      expect(convertSingle('INTEGER (0..255)')).toEqual({
        type: 'INTEGER',
        min: 0,
        max: 255,
      });
    });

    it('converts INTEGER with extensible constraint', () => {
      const schema = convertSingle('INTEGER (0..100, ...)');
      expect(schema).toEqual({
        type: 'INTEGER',
        min: 0,
        max: 100,
        extensible: true,
      });
    });

    it('converts OCTET STRING with SIZE constraint', () => {
      expect(convertSingle('OCTET STRING (SIZE (1..100))')).toEqual({
        type: 'OCTET STRING',
        minSize: 1,
        maxSize: 100,
      });
    });

    it('converts BIT STRING with fixed SIZE', () => {
      expect(convertSingle('BIT STRING (SIZE (8))')).toEqual({
        type: 'BIT STRING',
        fixedSize: 8,
      });
    });

    it('converts IA5String with SIZE constraint', () => {
      expect(convertSingle('IA5String (SIZE (1..50))')).toEqual({
        type: 'IA5String',
        minSize: 1,
        maxSize: 50,
      });
    });
  });

  describe('SEQUENCE', () => {
    it('converts simple SEQUENCE', () => {
      const schema = convertSingle('SEQUENCE { name IA5String, active BOOLEAN }');
      expect(schema).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'name', schema: { type: 'IA5String' } },
          { name: 'active', schema: { type: 'BOOLEAN' } },
        ],
      });
    });

    it('converts SEQUENCE with OPTIONAL fields', () => {
      const schema = convertSingle('SEQUENCE { name IA5String, extra INTEGER OPTIONAL }');
      expect(schema).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'name', schema: { type: 'IA5String' } },
          { name: 'extra', schema: { type: 'INTEGER' }, optional: true },
        ],
      });
    });

    it('converts SEQUENCE with DEFAULT values', () => {
      const schema = convertSingle('SEQUENCE { active BOOLEAN DEFAULT TRUE }');
      expect(schema).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'active', schema: { type: 'BOOLEAN' }, defaultValue: true },
        ],
      });
    });

    it('converts SEQUENCE with extension marker', () => {
      const schema = convertSingle('SEQUENCE { a BOOLEAN, ..., b INTEGER }');
      expect(schema).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'a', schema: { type: 'BOOLEAN' } },
        ],
        extensionFields: [
          { name: 'b', schema: { type: 'INTEGER' } },
        ],
      });
    });

    it('converts SEQUENCE with extension marker only (no additions)', () => {
      const schema = convertSingle('SEQUENCE { a BOOLEAN, ... }');
      expect(schema).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'a', schema: { type: 'BOOLEAN' } },
        ],
        extensionFields: [],
      });
    });

    it('converts SEQUENCE with OBJECT IDENTIFIER fields', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          TestType ::= SEQUENCE {
            name IA5String,
            oid OBJECT IDENTIFIER OPTIONAL,
            data OCTET STRING
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const seq = schemas['TestType'] as { type: string; fields: Array<{ name: string; schema: { type: string }; optional?: boolean }> };
      expect(seq.fields).toHaveLength(3);
      expect(seq.fields[0]).toEqual({ name: 'name', schema: { type: 'IA5String' } });
      expect(seq.fields[1]).toEqual({ name: 'oid', schema: { type: 'OBJECT IDENTIFIER' }, optional: true });
      expect(seq.fields[2]).toEqual({ name: 'data', schema: { type: 'OCTET STRING' } });
    });
  });

  describe('SEQUENCE OF', () => {
    it('converts SEQUENCE OF', () => {
      const schema = convertSingle('SEQUENCE OF INTEGER');
      expect(schema).toEqual({
        type: 'SEQUENCE OF',
        item: { type: 'INTEGER' },
      });
    });

    it('converts SEQUENCE OF with SIZE constraint', () => {
      const schema = convertSingle('SEQUENCE (SIZE (1..10)) OF INTEGER');
      expect(schema).toEqual({
        type: 'SEQUENCE OF',
        item: { type: 'INTEGER' },
        minSize: 1,
        maxSize: 10,
      });
    });
  });

  describe('CHOICE', () => {
    it('converts simple CHOICE', () => {
      const schema = convertSingle('CHOICE { flag BOOLEAN, count INTEGER }');
      expect(schema).toEqual({
        type: 'CHOICE',
        alternatives: [
          { name: 'flag', schema: { type: 'BOOLEAN' } },
          { name: 'count', schema: { type: 'INTEGER' } },
        ],
      });
    });

    it('converts CHOICE with extensions', () => {
      const schema = convertSingle('CHOICE { a BOOLEAN, ..., b INTEGER }');
      expect(schema).toEqual({
        type: 'CHOICE',
        alternatives: [
          { name: 'a', schema: { type: 'BOOLEAN' } },
        ],
        extensionAlternatives: [
          { name: 'b', schema: { type: 'INTEGER' } },
        ],
      });
    });

    it('converts CHOICE with extension marker only (no additions)', () => {
      const schema = convertSingle('CHOICE { a BOOLEAN, ... }');
      expect(schema).toEqual({
        type: 'CHOICE',
        alternatives: [
          { name: 'a', schema: { type: 'BOOLEAN' } },
        ],
        extensionAlternatives: [],
      });
    });
  });

  describe('ENUMERATED', () => {
    it('converts simple ENUMERATED', () => {
      const schema = convertSingle('ENUMERATED { red, green, blue }');
      expect(schema).toEqual({
        type: 'ENUMERATED',
        values: ['red', 'green', 'blue'],
      });
    });

    it('converts ENUMERATED with extensions', () => {
      const schema = convertSingle('ENUMERATED { red, green, ..., yellow }');
      expect(schema).toEqual({
        type: 'ENUMERATED',
        values: ['red', 'green'],
        extensionValues: ['yellow'],
      });
    });

    it('converts ENUMERATED with extension marker only (no values)', () => {
      const schema = convertSingle('ENUMERATED { red, green, ... }');
      expect(schema).toEqual({
        type: 'ENUMERATED',
        values: ['red', 'green'],
        extensionValues: [],
      });
    });
  });

  describe('type references', () => {
    it('resolves type references within the module', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          Inner ::= INTEGER (0..255)
          Outer ::= SEQUENCE { value Inner }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      expect(schemas['Outer']).toEqual({
        type: 'SEQUENCE',
        fields: [
          { name: 'value', schema: { type: 'INTEGER', min: 0, max: 255 } },
        ],
      });
    });

    it('throws on unresolved type reference', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          MyType ::= SEQUENCE { data UnknownType }
        END
      `);
      expect(() => convertModuleToSchemaNodes(mod)).toThrow('Unresolved type reference: UnknownType');
    });
  });

  describe('recursive type references', () => {
    it('emits $ref for direct self-referencing SEQUENCE field', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          TreeNode ::= SEQUENCE {
            value INTEGER (0..255),
            children SEQUENCE OF TreeNode OPTIONAL
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const node = schemas['TreeNode'] as any;
      expect(node.type).toBe('SEQUENCE');
      expect(node.fields[0]).toEqual({
        name: 'value',
        schema: { type: 'INTEGER', min: 0, max: 255 },
      });
      // The recursive reference should be a $ref, not inlined
      const childrenField = node.fields[1];
      expect(childrenField.name).toBe('children');
      expect(childrenField.optional).toBe(true);
      expect(childrenField.schema.type).toBe('SEQUENCE OF');
      expect(childrenField.schema.item).toEqual({ type: '$ref', ref: 'TreeNode' });
    });

    it('emits $ref for multiple self-referencing fields', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          ViaStation ::= SEQUENCE {
            name IA5String,
            alternativeRoutes SEQUENCE OF ViaStation OPTIONAL,
            route SEQUENCE OF ViaStation OPTIONAL
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const node = schemas['ViaStation'] as any;
      expect(node.type).toBe('SEQUENCE');
      expect(node.fields[0]).toEqual({ name: 'name', schema: { type: 'IA5String' } });
      expect(node.fields[1].schema.item).toEqual({ type: '$ref', ref: 'ViaStation' });
      expect(node.fields[2].schema.item).toEqual({ type: '$ref', ref: 'ViaStation' });
    });

    it('emits $ref for self-referencing CHOICE alternative', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          Expr ::= CHOICE {
            literal INTEGER (0..999),
            nested Expr
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const node = schemas['Expr'] as any;
      expect(node.type).toBe('CHOICE');
      expect(node.alternatives[0]).toEqual({
        name: 'literal',
        schema: { type: 'INTEGER', min: 0, max: 999 },
      });
      expect(node.alternatives[1]).toEqual({
        name: 'nested',
        schema: { type: '$ref', ref: 'Expr' },
      });
    });

    it('does not emit $ref for non-recursive type references', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          Inner ::= INTEGER (0..255)
          Outer ::= SEQUENCE {
            a Inner,
            b Inner
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const node = schemas['Outer'] as any;
      // Inner should be inlined, not a $ref
      expect(node.fields[0].schema).toEqual({ type: 'INTEGER', min: 0, max: 255 });
      expect(node.fields[1].schema).toEqual({ type: 'INTEGER', min: 0, max: 255 });
    });

    it('handles recursive type with constraints on the SEQUENCE OF', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          Category ::= SEQUENCE {
            name IA5String,
            subCategories SEQUENCE (SIZE (0..10)) OF Category OPTIONAL
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const node = schemas['Category'] as any;
      expect(node.fields[1].schema.type).toBe('SEQUENCE OF');
      expect(node.fields[1].schema.item).toEqual({ type: '$ref', ref: 'Category' });
      expect(node.fields[1].schema.minSize).toBe(0);
      expect(node.fields[1].schema.maxSize).toBe(10);
    });
  });

  describe('SchemaBuilder compatibility', () => {
    it('produces SchemaNode usable by SchemaBuilder', () => {
      const mod = parseAsn1Module(`
        Test DEFINITIONS ::= BEGIN
          MyType ::= SEQUENCE {
            id INTEGER (1..1000),
            name IA5String,
            active BOOLEAN OPTIONAL
          }
        END
      `);
      const schemas = convertModuleToSchemaNodes(mod);
      const codec = SchemaBuilder.build(schemas['MyType']);
      expect(codec).toBeDefined();
      expect(codec.encode).toBeInstanceOf(Function);
      expect(codec.decode).toBeInstanceOf(Function);
    });
  });
});
