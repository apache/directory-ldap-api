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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.schema.DitContentRule;
import org.apache.directory.api.ldap.model.schema.parsers.DitContentRuleDescriptionSchemaParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the DitContentRuleDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class DitContentRuleDescriptionSchemaParserTest
{
    /** the parser instance */
    private DitContentRuleDescriptionSchemaParser parser;


    @BeforeEach
    public void setUp() throws Exception
    {
        parser = new DitContentRuleDescriptionSchemaParser();
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
     * Tests NAME and its values
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testNames() throws ParseException
    {
        SchemaParserTestUtils.testNamesStrict( parser, "1.1", "" );
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
     * Tests OBSOLETE
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testObsolete() throws ParseException
    {
        SchemaParserTestUtils.testObsolete( parser, "1.1", "" );
    }


    /**
     * Test AUX and its values.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testAux() throws ParseException
    {
        String value = null;
        DitContentRule ditContentRule = null;

        // no AUX
        value = "( 1.1 )";
        ditContentRule = parser.parse( value );
        assertEquals( 0, ditContentRule.getAuxObjectClassOids().size() );

        // AUX simple numericoid
        value = "( 1.1 AUX 1.2.3 )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "1.2.3", ditContentRule.getAuxObjectClassOids().get( 0 ) );

        // AUX simple descr
        value = "( 1.1 AUX top )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "top", ditContentRule.getAuxObjectClassOids().get( 0 ) );

        // AUX single numericoid
        value = "( 1.1 AUX ( 1.2.3.4.5 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "1.2.3.4.5", ditContentRule.getAuxObjectClassOids().get( 0 ) );

        // AUX single descr
        value = "( 1.1 AUX ( A-Z-0-9 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "A-Z-0-9", ditContentRule.getAuxObjectClassOids().get( 0 ) );

        // AUX multi numericoid
        value = "( 1.1 AUX ( 1.2.3 $ 1.2.3.4.5 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 2, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "1.2.3", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "1.2.3.4.5", ditContentRule.getAuxObjectClassOids().get( 1 ) );

        // AUX multi descr
        value = "( 1.1 AUX ( top1 $ top2 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 2, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "top1", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "top2", ditContentRule.getAuxObjectClassOids().get( 1 ) );

        // AUX multi mixed
        value = "( 1.1 AUX ( top1 $ 1.2.3.4 $ top2 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 3, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "top1", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "1.2.3.4", ditContentRule.getAuxObjectClassOids().get( 1 ) );
        assertEquals( "top2", ditContentRule.getAuxObjectClassOids().get( 2 ) );

        // AUX multi mixed no space
        value = "(1.1 AUX(TOP-1$1.2.3.4$TOP-2))";

        try
        {  
            ditContentRule = parser.parse( value );
            fail( "Exception expected, space expected" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // AUX multi mixed many spaces
        value = "(          1.1          AUX          (          top1          $          1.2.3.4$top2          )          )";
        ditContentRule = parser.parse( value );
        assertEquals( 3, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "top1", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "1.2.3.4", ditContentRule.getAuxObjectClassOids().get( 1 ) );
        assertEquals( "top2", ditContentRule.getAuxObjectClassOids().get( 2 ) );

        // no quote allowed
        value = "( 1.1 AUX 'top' )";

        try
        {  
            ditContentRule = parser.parse( value );
            fail( "Exception expected, no quote allowed" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // quoted value
        value = "( 1.1 AUX '1.2.3.4' )";

        try
        {  
            ditContentRule = parser.parse( value );
            fail( "Exception expected, no quote allowed" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no $ separator
        value = "( 1.1 AUX ( top1 top2 ) )";
        ditContentRule = parser.parse( value );
        assertEquals( 2, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "top1", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "top2", ditContentRule.getAuxObjectClassOids().get( 1 ) );

        // invalid character
        value = "( 1.1 AUX 1.2.3.4.A )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, invalid AUX '1.2.3.4.A' (invalid character)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // empty AUX
        value = "( 1.1 AUX )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, no AUX value" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // invalid start
        value = "( 1.1 AUX ( top1 $ -top2 ) )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, invalid AUX '-top' (starts with hypen)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Test MUST and its values.
     * Very similar to AUX, so here are less test cases. 
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testMust() throws ParseException
    {
        String value = null;
        DitContentRule ditContentRule = null;

        // no MUST
        value = "( 1.1 )";
        ditContentRule = parser.parse( value );
        assertEquals( 0, ditContentRule.getMustAttributeTypeOids().size() );

        // MUST simple numericoid
        value = "( 1.1 MUST 1.2.3 )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getMustAttributeTypeOids().size() );
        assertEquals( "1.2.3", ditContentRule.getMustAttributeTypeOids().get( 0 ) );

        // MUST mulitple
        value = "(1.1 MUST (cn\rsn       $1.22.33.44.55            objectClass\t))";
        ditContentRule = parser.parse( value );
        assertEquals( 4, ditContentRule.getMustAttributeTypeOids().size() );
        assertEquals( "cn", ditContentRule.getMustAttributeTypeOids().get( 0 ) );
        assertEquals( "sn", ditContentRule.getMustAttributeTypeOids().get( 1 ) );
        assertEquals( "1.22.33.44.55", ditContentRule.getMustAttributeTypeOids().get( 2 ) );
        assertEquals( "objectClass", ditContentRule.getMustAttributeTypeOids().get( 3 ) );

        // no MUST values
        value = "( 1.1 MUST )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, no MUST value" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // invalid value
        value = "( 1.1 MUST ( c_n ) )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, invalid value c_n" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Test MAY and its values.
     * Very similar to AUX, so here are less test cases. 
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testMay() throws ParseException
    {
        String value = null;
        DitContentRule ditContentRule = null;

        // no MAY
        value = "( 1.1 )";
        ditContentRule = parser.parse( value );
        assertEquals( 0, ditContentRule.getMayAttributeTypeOids().size() );

        // MAY simple numericoid
        value = "( 1.1 MAY 1.2.3 )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getMayAttributeTypeOids().size() );
        assertEquals( "1.2.3", ditContentRule.getMayAttributeTypeOids().get( 0 ) );

        // MAY mulitple
        value = "(1.1 MAY (cn$sn       $1.22.33.44.55         $  objectClass   ))";
        ditContentRule = parser.parse( value );
        assertEquals( 4, ditContentRule.getMayAttributeTypeOids().size() );
        assertEquals( "cn", ditContentRule.getMayAttributeTypeOids().get( 0 ) );
        assertEquals( "sn", ditContentRule.getMayAttributeTypeOids().get( 1 ) );
        assertEquals( "1.22.33.44.55", ditContentRule.getMayAttributeTypeOids().get( 2 ) );
        assertEquals( "objectClass", ditContentRule.getMayAttributeTypeOids().get( 3 ) );

        // invalid value
        value = "( 1.1 MAY ( c_n ) )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, invalid value c_n" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Test NOT and its values.
     * Very similar to AUX, so here are less test cases. 
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testNot() throws ParseException
    {
        String value = null;
        DitContentRule ditContentRule = null;

        // no NOT
        value = "( 1.1 )";
        ditContentRule = parser.parse( value );
        assertEquals( 0, ditContentRule.getNotAttributeTypeOids().size() );

        // NOT simple numericoid
        value = "( 1.1 NOT 1.2.3 )";
        ditContentRule = parser.parse( value );
        assertEquals( 1, ditContentRule.getNotAttributeTypeOids().size() );
        assertEquals( "1.2.3", ditContentRule.getNotAttributeTypeOids().get( 0 ) );

        // NOT mulitple
        value = "(1.1 NOT (cn\nsn\t$1.22.33.44.55         $  objectClass   ))";
        ditContentRule = parser.parse( value );
        assertEquals( 4, ditContentRule.getNotAttributeTypeOids().size() );
        assertEquals( "cn", ditContentRule.getNotAttributeTypeOids().get( 0 ) );
        assertEquals( "sn", ditContentRule.getNotAttributeTypeOids().get( 1 ) );
        assertEquals( "1.22.33.44.55", ditContentRule.getNotAttributeTypeOids().get( 2 ) );
        assertEquals( "objectClass", ditContentRule.getNotAttributeTypeOids().get( 3 ) );

        // invalid value
        value = "( 1.1 NOT ( c_n ) )";
        try
        {
            ditContentRule = parser.parse( value );
            fail( "Exception expected, invalid value c_n" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
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
     * Test full object class description.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testFull() throws ParseException
    {
        String value = null;
        DitContentRule ditContentRule = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE AUX ( 2.3.4.5.6.7.8.9.0.1 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) MUST ( 2.3.4.5.6.7.8.9.0.1.2 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) MAY ( 2.3.4.5.6.7.8.9.0.1.2.3 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) NOT ( 2.3.4.5.6.7.8.9.0.1.2.3.4 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )";
        ditContentRule = parser.parse( value );

        assertEquals( "1.2.3.4.5.6.7.8.9.0", ditContentRule.getOid() );
        assertEquals( 2, ditContentRule.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditContentRule.getNames()
            .get( 0 ) );
        assertEquals( "test", ditContentRule.getNames().get( 1 ) );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", ditContentRule.getDescription() );
        assertTrue( ditContentRule.isObsolete() );
        assertEquals( 2, ditContentRule.getAuxObjectClassOids().size() );
        assertEquals( "2.3.4.5.6.7.8.9.0.1", ditContentRule.getAuxObjectClassOids().get( 0 ) );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditContentRule
            .getAuxObjectClassOids().get( 1 ) );
        assertEquals( 2, ditContentRule.getMustAttributeTypeOids().size() );
        assertEquals( "2.3.4.5.6.7.8.9.0.1.2", ditContentRule.getMustAttributeTypeOids().get( 0 ) );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditContentRule
            .getMustAttributeTypeOids()
            .get( 1 ) );
        assertEquals( 2, ditContentRule.getMayAttributeTypeOids().size() );
        assertEquals( "2.3.4.5.6.7.8.9.0.1.2.3", ditContentRule.getMayAttributeTypeOids().get( 0 ) );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditContentRule
            .getMayAttributeTypeOids()
            .get( 1 ) );
        assertEquals( 2, ditContentRule.getNotAttributeTypeOids().size() );
        assertEquals( "2.3.4.5.6.7.8.9.0.1.2.3.4", ditContentRule.getNotAttributeTypeOids().get( 0 ) );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditContentRule
            .getNotAttributeTypeOids()
            .get( 1 ) );
        assertEquals( 3, ditContentRule.getExtensions().size() );
        assertNotNull( ditContentRule.getExtension( "X-TEST-a" ) );
        assertEquals( 2, ditContentRule.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", ditContentRule.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", ditContentRule.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( ditContentRule.getExtension( "X-TEST-b" ) );
        assertEquals( 2, ditContentRule.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", ditContentRule.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", ditContentRule.getExtension( "X-TEST-b" ).get( 1 ) );

        // Check the schema
        assertNotNull( ditContentRule.getExtension( MetaSchemaConstants.X_SCHEMA_AT ) );
        assertEquals( 1, ditContentRule.getExtension( MetaSchemaConstants.X_SCHEMA_AT ).size() );
        assertEquals( MetaSchemaConstants.SCHEMA_OTHER, ditContentRule.getExtension( "X-SCHEMA" ).get(0) );
    }


    /**
     * Test unique elements.
     */
    @Test
    public void testUniqueElements()
    {
        String[] testValues = new String[]
            { "( 1.1 NAME 'test1' NAME 'test2' )", "( 1.1 DESC 'test1' DESC 'test2' )", "( 1.1 OBSOLETE OBSOLETE )",
                "( 1.1 AUX test1 AUX test2 )", "( 1.1 MUST test1 MUST test2 )", "( 1.1 MAY test1 MAY test2 )",
                "( 1.1 NOT test1 NOT test2 )", "( 1.1 X-TEST 'test1' X-TEST 'test2' )" };
        SchemaParserTestUtils.testUnique( parser, testValues );
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
                "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )",
                "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )",
                "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE AUX ( 2.3.4.5.6.7.8.9.0.1 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) MUST ( 2.3.4.5.6.7.8.9.0.1.2 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) MAY ( 2.3.4.5.6.7.8.9.0.1.2.3 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) NOT ( 2.3.4.5.6.7.8.9.0.1.2.3.4 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )" };
        SchemaParserTestUtils.testMultiThreaded( parser, testValues );
    }
}
