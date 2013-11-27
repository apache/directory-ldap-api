/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */package org.apache.directory.api.ldap.model.schema;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

import org.apache.directory.api.ldap.model.schema.parsers.AttributeTypeDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.ObjectClassDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.OpenLdapSchemaParser;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaObjectRendererTest
{

    private MutableObjectClass objectClassSimple;
    private MutableObjectClass objectClassComplex;

    private MutableAttributeType attributeTypeSimple;
    private MutableAttributeType attributeTypeComplex;


    @Before
    public void setUp()
    {
        objectClassSimple = new MutableObjectClass( "1.2.3.4" );
        objectClassSimple.setNames( "name0" );
        objectClassSimple.setMustAttributeTypeOids( Arrays.asList( "att0" ) );
        objectClassSimple.setSchemaName( "dummy" );

        objectClassComplex = new MutableObjectClass( "1.2.3.4" );
        objectClassComplex.setNames( "name1", "name2" );
        objectClassComplex.setDescription( "description with 'quotes'" );
        objectClassComplex.setObsolete( true );
        objectClassComplex.setSuperiorOids( Collections.singletonList( "1.3.5.7" ) );
        objectClassComplex.setType( ObjectClassTypeEnum.AUXILIARY );
        objectClassComplex.setMustAttributeTypeOids( Arrays.asList( "att1", "att2" ) );
        objectClassComplex.setMayAttributeTypeOids( Arrays.asList( "att3", "att4" ) );
        objectClassComplex.setSchemaName( "dummy" );

        attributeTypeSimple = new MutableAttributeType( "1.2.3.4" );
        attributeTypeSimple.setNames( "name0" );
        attributeTypeSimple.setEqualityOid( "matchingRule0" );
        attributeTypeSimple.setSyntaxOid( "2.3.4.5" );
        attributeTypeSimple.setSyntaxLength( 512 );
        attributeTypeSimple.setCollective( true );
        attributeTypeSimple.setSchemaName( "dummy" );

        attributeTypeComplex = new MutableAttributeType( "1.2.3.4" );
        attributeTypeComplex.setNames( "name1", "name2" );
        attributeTypeComplex.setDescription( "description with 'quotes'" );
        attributeTypeComplex.setObsolete( true );
        attributeTypeComplex.setSuperiorOid( "superAttr" );
        attributeTypeComplex.setEqualityOid( "matchingRule1" );
        attributeTypeComplex.setOrderingOid( "matchingRule2" );
        attributeTypeComplex.setSubstringOid( "matchingRule3" );
        attributeTypeComplex.setSingleValued( true );
        attributeTypeComplex.setUserModifiable( false );
        attributeTypeComplex.setUsage( UsageEnum.DIRECTORY_OPERATION );
        attributeTypeComplex.setSchemaName( "dummy" );
    }


    @Test
    public void testOpenLdapSchemaRendererObjectClassMinimal()
    {
        String actual = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( new ObjectClass( "1.2.3" ) );
        String expected = "objectclass ( 1.2.3\n\tSTRUCTURAL\n)";
        assertEquals( expected, actual );
    }


    @Test
    public void testOpenLdapSchemaRendererObjectClassSimple()
    {
        String actual = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( objectClassSimple );
        String expected = "objectclass ( 1.2.3.4 NAME 'name0'\n\tSTRUCTURAL\n\tMUST att0\n)";
        assertEquals( expected, actual );
    }


    @Test
    public void testOpenLdapSchemaRendererObjectClassComplex()
    {
        String actual = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( objectClassComplex );
        String expected = "objectclass ( 1.2.3.4 NAME ( 'name1' 'name2' )\n\tDESC 'description with \\27quotes\\27'\n\tOBSOLETE\n\tSUP 1.3.5.7\n\tAUXILIARY\n\tMUST ( att1 $ att2 )\n\tMAY ( att3 $ att4 )\n)";
        assertEquals( expected, actual );
    }


    @Test
    public void testOpenLdapSchemaRendererAndParserRoundtripObjectClassSimple() throws Exception
    {
        testOpenLdapSchemaRendererAndParserRountrip( objectClassSimple );
    }


    @Test
    public void testOpenLdapSchemaRendererAndParserRoundtripObjectClassComplex() throws Exception
    {
        testOpenLdapSchemaRendererAndParserRountrip( objectClassComplex );
    }


    private void testOpenLdapSchemaRendererAndParserRountrip( ObjectClass original ) throws Exception
    {
        // must unset schema name because OpenLdapSchemaParser doesn't know about schema name
        original.setSchemaName( null );

        String renderedOriginal = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( original );
        ObjectClass parsed = ( ObjectClass ) new OpenLdapSchemaParser().parse( renderedOriginal );
        String renderedParsed = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( parsed );

        assertTrue( original.equals( parsed ) );
        assertTrue( renderedOriginal.equals( renderedParsed ) );
    }


    @Test
    public void testSubschemSubentryRendererObjectClassMinimal()
    {
        String actual = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( new ObjectClass( "1.2.3" ) );
        String expected = "( 1.2.3 STRUCTURAL X-SCHEMA 'null' )";
        assertEquals( expected, actual );
    }


    @Test
    public void testSubschemSubentryRendererObjectClassSimple()
    {
        String actual = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( objectClassSimple );
        String expected = "( 1.2.3.4 NAME 'name0' STRUCTURAL MUST att0 X-SCHEMA 'dummy' )";
        assertEquals( expected, actual );
    }


    @Test
    public void testSubschemSubentryRendererObjectClassComplex()
    {
        String actual = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( objectClassComplex );
        String expected = "( 1.2.3.4 NAME ( 'name1' 'name2' ) DESC 'description with \\27quotes\\27' OBSOLETE SUP 1.3.5.7 AUXILIARY MUST ( att1 $ att2 ) MAY ( att3 $ att4 ) X-SCHEMA 'dummy' )";
        assertEquals( expected, actual );
    }


    @Test
    public void testSubschemSubentryRendererAndParserRoundtripObjectClassSimple() throws ParseException
    {
        testSubschemSubentryRendererAndParserRoundtrip( objectClassSimple );
    }


    @Test
    public void testSubschemSubentryRendererAndParserRoundtripObjectClassComplex() throws ParseException
    {
        testSubschemSubentryRendererAndParserRoundtrip( objectClassComplex );
    }


    private void testSubschemSubentryRendererAndParserRoundtrip( ObjectClass original ) throws ParseException
    {
        String renderedOriginal = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( original );
        ObjectClass parsed = new ObjectClassDescriptionSchemaParser().parse( renderedOriginal );
        String renderedParsed = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( parsed );

        assertTrue( original.equals( parsed ) );
        assertTrue( renderedOriginal.equals( renderedParsed ) );
    }


    @Test
    public void testOpenLdapSchemaRendererAttributeTypeSimple()
    {
        String actual = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( attributeTypeSimple );
        String expected = "attributetype ( 1.2.3.4 NAME 'name0'\n\tEQUALITY matchingRule0\n\tSYNTAX 2.3.4.5{512}\n\tCOLLECTIVE\n\tUSAGE userApplications\n)";
        assertEquals( expected, actual );
    }


    @Test
    public void testOpenLdapSchemaRendererAttributeTypeComplex()
    {
        String actual = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( attributeTypeComplex );
        String expected = "attributetype ( 1.2.3.4 NAME ( 'name1' 'name2' )\n\tDESC 'description with \\27quotes\\27'\n\tOBSOLETE\n\tSUP superAttr\n\tEQUALITY matchingRule1\n\tORDERING matchingRule2\n\tSUBSTR matchingRule3\n\tSINGLE-VALUE\n\tNO-USER-MODIFICATION\n\tUSAGE directoryOperation\n)";
        assertEquals( expected, actual );
    }


    @Test
    public void testOpenLdapSchemaRendererAndParserRoundtripAttributeTypeSimple() throws Exception
    {
        testOpenLdapSchemaRendererAndParserRountrip( attributeTypeSimple );
    }


    @Test
    public void testOpenLdapSchemaRendererAndParserRoundtripAttributeTypeComplex() throws Exception
    {
        testOpenLdapSchemaRendererAndParserRountrip( attributeTypeComplex );
    }


    private void testOpenLdapSchemaRendererAndParserRountrip( AttributeType original ) throws Exception
    {
        // must unset schema name because OpenLdapSchemaParser doesn't know about schema name
        original.setSchemaName( null );

        String renderedOriginal = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( original );
        AttributeType parsed = ( AttributeType ) new OpenLdapSchemaParser().parse( renderedOriginal );
        String renderedParsed = SchemaObjectRenderer.OPEN_LDAP_SCHEMA_RENDERER.render( parsed );

        assertTrue( original.equals( parsed ) );
        assertTrue( renderedOriginal.equals( renderedParsed ) );
    }


    @Test
    public void testSubschemSubentryRendererAttributeTypeSimple()
    {
        String actual = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( attributeTypeSimple );
        String expected = "( 1.2.3.4 NAME 'name0' EQUALITY matchingRule0 SYNTAX 2.3.4.5{512} COLLECTIVE USAGE userApplications X-SCHEMA 'dummy' )";
        assertEquals( expected, actual );
    }


    @Test
    public void testSubschemSubentryRendererAttributeTypeComplex()
    {
        String actual = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( attributeTypeComplex );
        String expected = "( 1.2.3.4 NAME ( 'name1' 'name2' ) DESC 'description with \\27quotes\\27' OBSOLETE SUP superAttr EQUALITY matchingRule1 ORDERING matchingRule2 SUBSTR matchingRule3 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation X-SCHEMA 'dummy' )";
        assertEquals( expected, actual );
    }


    @Test
    public void testSubschemSubentryRendererAndParserRoundtripAttributeTypeSimple() throws ParseException
    {
        testSubschemSubentryRendererAndParserRoundtrip( attributeTypeSimple );
    }


    @Test
    public void testSubschemSubentryRendererAndParserRoundtripAttributeTypeComplex() throws ParseException
    {
        testSubschemSubentryRendererAndParserRoundtrip( attributeTypeComplex );
    }


    private void testSubschemSubentryRendererAndParserRoundtrip( AttributeType original ) throws ParseException
    {
        String renderedOriginal = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( original );
        AttributeType parsed = new AttributeTypeDescriptionSchemaParser().parse( renderedOriginal );
        String renderedParsed = SchemaObjectRenderer.SUBSCHEMA_SUBENTRY_RENDERER.render( parsed );

        assertTrue( original.equals( parsed ) );
        assertTrue( renderedOriginal.equals( renderedParsed ) );
    }
}
