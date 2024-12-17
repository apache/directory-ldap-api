/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    https://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.api.ldap.model.schema.syntaxes.parser;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.parsers.LdapSyntaxDescriptionSchemaParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the LdapSyntaxDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdapSyntaxDescriptionSchemaParserTest
{
    /** the parser instance */
    private LdapSyntaxDescriptionSchemaParser parser;


    @BeforeEach
    public void setUp() throws Exception
    {
        parser = new LdapSyntaxDescriptionSchemaParser();
    }


    @AfterEach
    public void tearDown() throws Exception
    {
        parser = null;
    }


    /**
     * Test numericoid
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testNumericOid() throws ParseException
    {
        SchemaParserTestUtils.testNumericOid( parser, "" );
    }


    /**
     * Tests DESC
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testDescription() throws ParseException
    {
        SchemaParserTestUtils.testDescription( parser, "1.1", "" );
    }


    /**
     * Test extensions.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testExtensions() throws ParseException
    {
        SchemaParserTestUtils.testExtensions( parser, "1.1", "" );
    }


    /**
     * Test full sytax description.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testFull() throws ParseException
    {
        String value = null;
        LdapSyntax ldapSyntax = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )";
        ldapSyntax = parser.parse( value );

        assertEquals( "1.2.3.4.5.6.7.8.9.0", ldapSyntax.getOid() );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", ldapSyntax.getDescription() );
        assertEquals( 2, ldapSyntax.getExtensions().size() );
        assertNotNull( ldapSyntax.getExtension( "X-TEST-a" ) );
        assertEquals( 2, ldapSyntax.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", ldapSyntax.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", ldapSyntax.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( ldapSyntax.getExtension( "X-TEST-b" ) );
        assertEquals( 2, ldapSyntax.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", ldapSyntax.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", ldapSyntax.getExtension( "X-TEST-b" ).get( 1 ) );
        assertEquals( value, ldapSyntax.getSpecification() );
    }


    /**
     * Test unique elements.
     */
    @Test
    public void testUniqueElements()
    {
        String[] testValues = new String[]
            { "( 1.1 DESC 'test1' DESC 'test2' )", "( 1.1 X-TEST 'test1' X-TEST 'test2' )" };
        SchemaParserTestUtils.testUnique( parser, testValues );
    }


    ////////////////////////////////////////////////////////////////
    //         Some real-world attribute type definitions         //
    ////////////////////////////////////////////////////////////////

    @Test
    public void testRfcBinary() throws ParseException
    {
        String value = "( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' X-NOT-HUMAN-READABLE 'TRUE' )";
        LdapSyntax ldapSyntax = parser.parse( value );

        assertEquals( "1.3.6.1.4.1.1466.115.121.1.5", ldapSyntax.getOid() );
        assertEquals( "Binary", ldapSyntax.getDescription() );
        assertEquals( 1, ldapSyntax.getExtensions().size() );
        assertNotNull( ldapSyntax.getExtension( "X-NOT-HUMAN-READABLE" ) );
        assertEquals( 1, ldapSyntax.getExtension( "X-NOT-HUMAN-READABLE" ).size() );
        assertEquals( "TRUE", ldapSyntax.getExtension( "X-NOT-HUMAN-READABLE" ).get( 0 ) );
        assertEquals( value, ldapSyntax.getSpecification() );
    }


    /**
     * Tests the parse of a simple AttributeType with the schema extension.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testSyntaxWithExtensions() throws ParseException
    {
        String substrate = "( 1.3.6.1.4.1.18060.0.4.0.2.10000 DESC 'bogus description' X-SCHEMA 'blah' X-NOT-HUMAN-READABLE 'false' )";
        LdapSyntax ldapSyntax = parser.parse( substrate );
        assertEquals( "1.3.6.1.4.1.18060.0.4.0.2.10000", ldapSyntax.getOid() );
        assertEquals( "bogus description", ldapSyntax.getDescription() );
        assertNotNull( ldapSyntax.getExtension( "X-NOT-HUMAN-READABLE" ) );
        assertEquals( substrate, ldapSyntax.getSpecification() );
    }


    /**
     * Tests the multithreaded use of a single parser.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testMultiThreaded() throws ParseException
    {
        String[] testValues = new String[]
            {
                "( 1.1 )",
                "( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )",
                "( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' X-NOT-HUMAN-READABLE 'TRUE' )",
                "( 1.2.3.4.5.6.7.8.9.0 DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )" };
        SchemaParserTestUtils.testMultiThreaded( parser, testValues );
    }


    /**
     * Tests quirks mode.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testQuirksMode() throws ParseException
    {
        SchemaParserTestUtils.testQuirksMode( parser, "" );

        try
        {
            parser.setQuirksMode( true );

            // ensure all other test pass in quirks mode
            testNumericOid();
            testDescription();
            testExtensions();
            testFull();
            testUniqueElements();
            testRfcBinary();
            testSyntaxWithExtensions();
            testMultiThreaded();
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }
}
