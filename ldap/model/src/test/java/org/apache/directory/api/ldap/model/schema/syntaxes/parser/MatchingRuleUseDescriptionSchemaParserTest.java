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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.schema.MatchingRuleUse;
import org.apache.directory.api.ldap.model.schema.parsers.MatchingRuleUseDescriptionSchemaParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the MatchingRuleUseDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class MatchingRuleUseDescriptionSchemaParserTest
{
    /** the parser instance */
    private MatchingRuleUseDescriptionSchemaParser parser;


    @BeforeEach
    public void setUp() throws Exception
    {
        parser = new MatchingRuleUseDescriptionSchemaParser();
    }


    @AfterEach
    public void tearDown() throws Exception
    {
        parser = null;
    }


    @Test
    public void testNumericOid() throws ParseException
    {
        SchemaParserTestUtils.testNumericOid( parser, "APPLIES 1.1" );
    }


    @Test
    public void testNamesRelaxed() throws ParseException
    {
        SchemaParserTestUtils.testNamesRelaxed( parser, "1.1", "APPLIES 1.1" );
    }


    @Test
    public void testNamesStrict() throws ParseException
    {
        SchemaParserTestUtils.testNamesStrict( parser, "1.1", "APPLIES 1.1" );
    }


    @Test
    public void testDescription() throws ParseException
    {
        SchemaParserTestUtils.testDescription( parser, "1.1", "APPLIES 1.1" );
    }


    @Test
    public void testObsolete() throws ParseException
    {
        SchemaParserTestUtils.testObsolete( parser, "1.1", "APPLIES 1.1" );
    }


    @Test
    public void testApplies() throws ParseException
    {

        String value = null;
        MatchingRuleUse matchingRuleUse = null;

        // APPLIES simple numericoid
        value = "( 1.1 APPLIES 1.2.3.4.5.6.7.8.9.0 )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "1.2.3.4.5.6.7.8.9.0", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );

        // SUP simple descr
        value = "( 1.1 APPLIES abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", matchingRuleUse
            .getApplicableAttributeOids().get( 0 ) );

        // APPLIES single numericoid
        value = "( 1.1 APPLIES ( 1.2.3.4567.890 ) )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "1.2.3.4567.890", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );

        // APPLIES single descr
        value = "(1.1 APPLIES (a-z-A-Z-0-9))";
        matchingRuleUse = parser.parse( value );
        assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "a-z-A-Z-0-9", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );

        // APPLIES multi numericoid
        value = "( 1.1 APPLIES ( 1.2.3 $ 1.2.4.5.6 $ 1.2.7.8.90 ) )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 3, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "1.2.3", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "1.2.4.5.6", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );
        assertEquals( "1.2.7.8.90", matchingRuleUse.getApplicableAttributeOids().get( 2 ) );

        // APPLIES multi descr
        value = "( 1.1 APPLIES ( test1 $ test2 ) )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 2, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "test1", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "test2", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );

        // APPLIES multi mixed, tabs
        value = "\t(\t1.1\tAPPLIES\t(\ttest1\t$\t1.2.3.4\t$\ttest2\t)\t)\t";
        matchingRuleUse = parser.parse( value );
        assertEquals( 3, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "test1", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "1.2.3.4", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );
        assertEquals( "test2", matchingRuleUse.getApplicableAttributeOids().get( 2 ) );

        // APPLIES multi mixed no space
        value = "(1.1 APPLIES(TEST-1$1.2.3.4$TEST-2))";
        
        try 
        {
            matchingRuleUse = parser.parse( value );
            fail( "Exception expected, SPACES expected" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // APPLIES multi mixed many spaces
        value = "(          1.1          APPLIES          (          test1          $          1.2.3.4$test2          )          )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 3, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "test1", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "1.2.3.4", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );
        assertEquals( "test2", matchingRuleUse.getApplicableAttributeOids().get( 2 ) );

        // quoted value
        if ( parser.isQuirksMode() )
        {
            value = "( 1.1 APPLIES 'test' )";
            matchingRuleUse = parser.parse( value );
            assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
            assertEquals( "test", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
    
            // quoted value
            value = "( 1.1 APPLIES '1.2.3.4' )";
            matchingRuleUse = parser.parse( value );
            assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );
            assertEquals( "1.2.3.4", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        }
        else
        {
            value = "( 1.1 APPLIES 'test' )";
            
            try
            {
                matchingRuleUse = parser.parse( value );
                fail( "Exception expected, quote not allowed in APPLIES" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // quoted value
            value = "( 1.1 APPLIES '1.2.3.4' )";
            
            try
            {
                matchingRuleUse = parser.parse( value );
                fail( "Exception expected, quote not allowed in APPLIES" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }

        // no $ separator
        value = "( 1.1 APPLIES ( test1 test2 ) )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 2, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "test1", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "test2", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );

        // invalid character
        value = "( 1.1 APPLIES 1.2.3.4.A )";
        try
        {
            matchingRuleUse = parser.parse( value );
            fail( "Exception expected, invalid APPLIES '1.2.3.4.A' (invalid character)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // empty APPLIES
        value = "( 1.1 APPLIES )";
        try
        {
            matchingRuleUse = parser.parse( value );
            fail( "Exception expected, no APPLIES value" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // APPLIES must only appear once
        value = "( 1.1 APPLIES test1 APPLIES test2 )";
        try
        {
            matchingRuleUse = parser.parse( value );
            fail( "Exception expected, APPLIES appears twice" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        if ( !parser.isQuirksMode() )
        {
            // APPLIES is required
            value = "( 1.1 )";
            try
            {
                matchingRuleUse = parser.parse( value );
                fail( "Exception expected, APPLIES is required" );
            }
            catch ( ParseException pe )
            {
                // expected
            }

            // invalid start
            value = "( 1.1 APPLIES ( test1 $ -test2 ) )";
            try
            {
                matchingRuleUse = parser.parse( value );
                fail( "Exception expected, invalid APPLIES '-test' (starts with hypen)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }
    }


    @Test
    public void testExtensions() throws ParseException
    {
        SchemaParserTestUtils.testExtensions( parser, "1.1", "APPLIES 1.1" );
    }


    @Test
    public void testFull() throws ParseException
    {
        String value = null;
        MatchingRuleUse matchingRuleUse = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE APPLIES ( 0.1.2.3.4.5.6.7.8.9 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )";
        matchingRuleUse = parser.parse( value );

        assertEquals( "1.2.3.4.5.6.7.8.9.0", matchingRuleUse.getOid() );
        assertEquals( 2, matchingRuleUse.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", matchingRuleUse.getNames()
            .get( 0 ) );
        assertEquals( "test", matchingRuleUse.getNames().get( 1 ) );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", matchingRuleUse.getDescription() );
        assertTrue( matchingRuleUse.isObsolete() );
        assertEquals( 2, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", matchingRuleUse
            .getApplicableAttributeOids().get( 1 ) );
        assertEquals( 3, matchingRuleUse.getExtensions().size() );
        assertNotNull( matchingRuleUse.getExtension( "X-TEST-a" ) );
        assertEquals( 2, matchingRuleUse.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", matchingRuleUse.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", matchingRuleUse.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( matchingRuleUse.getExtension( "X-TEST-b" ) );
        assertEquals( 2, matchingRuleUse.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", matchingRuleUse.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", matchingRuleUse.getExtension( "X-TEST-b" ).get( 1 ) );

        // Check the schema
        assertNotNull( matchingRuleUse.getExtension( MetaSchemaConstants.X_SCHEMA_AT ) );
        assertEquals( 1, matchingRuleUse.getExtension( MetaSchemaConstants.X_SCHEMA_AT ).size() );
        assertEquals( MetaSchemaConstants.SCHEMA_OTHER, matchingRuleUse.getExtension( "X-SCHEMA" ).get(0) );
    }


    /**
     * Test unique elements.
     */
    @Test
    public void testUniqueElements()
    {
        String[] testValues = new String[]
            { "( 1.1 APPLIES 1.1 NAME 'test1' NAME 'test2' )", "( 1.1 APPLIES 1.1 DESC 'test1' DESC 'test2' )",
                "( 1.1 APPLIES 1.1 OBSOLETE OBSOLETE )", "( 1.1 APPLIES 1.1 APPLIES test1 APPLIES test2 )",
                "( 1.1 APPLIES 1.1 X-TEST 'test1' X-TEST 'test2' )" };
        SchemaParserTestUtils.testUnique( parser, testValues );
    }


    /**
     * Test required elements.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testRequiredElements() throws ParseException
    {
        String value = null;
        MatchingRuleUse matchingRuleUse = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 APPLIES a )";
        matchingRuleUse = parser.parse( value );
        assertEquals( 1, matchingRuleUse.getApplicableAttributeOids().size() );

        if ( !parser.isQuirksMode() )
        {
            value = "( 1.2.3.4.5.6.7.8.9.0 )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, APPLIES is required" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }
    }


    ////////////////////////////////////////////////////////////////
    //       Some real-world matching rule use descriptons        //
    ////////////////////////////////////////////////////////////////

    @Test
    public void testOpenldap1() throws ParseException
    {
        String value = "( 2.5.13.17 NAME 'octetStringMatch' APPLIES ( javaSerializedData $ userPassword ) )";
        MatchingRuleUse matchingRuleUse = parser.parse( value );

        assertEquals( "2.5.13.17", matchingRuleUse.getOid() );
        assertEquals( 1, matchingRuleUse.getNames().size() );
        assertEquals( "octetStringMatch", matchingRuleUse.getNames().get( 0 ) );
        assertNull( matchingRuleUse.getDescription() );
        assertFalse( matchingRuleUse.isObsolete() );
        assertEquals( 2, matchingRuleUse.getApplicableAttributeOids().size() );
        assertEquals( "javaSerializedData", matchingRuleUse.getApplicableAttributeOids().get( 0 ) );
        assertEquals( "userPassword", matchingRuleUse.getApplicableAttributeOids().get( 1 ) );
        assertEquals( 1, matchingRuleUse.getExtensions().size() );

        // Check the schema
        assertNotNull( matchingRuleUse.getExtension( MetaSchemaConstants.X_SCHEMA_AT ) );
        assertEquals( 1, matchingRuleUse.getExtension( MetaSchemaConstants.X_SCHEMA_AT ).size() );
        assertEquals( MetaSchemaConstants.SCHEMA_OTHER, matchingRuleUse.getExtension( "X-SCHEMA" ).get(0) );
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
                "( 1.1 APPLIES 1.1 )",
                "( 2.5.13.17 NAME 'octetStringMatch' APPLIES ( javaSerializedData $ userPassword ) )",
                "( 2.5.13.1 NAME 'distinguishedNameMatch' APPLIES ( memberOf $ dITRedirect $ associatedName $ secretary $ documentAuthor $ manager $ seeAlso $ roleOccupant $ owner $ member $ distinguishedName $ aliasedObjectName $ namingContexts $ subschemaSubentry $ modifiersName $ creatorsName ) )",
                "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE APPLIES ( 0.1.2.3.4.5.6.7.8.9 $ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )" };
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
        SchemaParserTestUtils.testQuirksMode( parser, "APPLIES 1.1" );

        try
        {
            parser.setQuirksMode( true );

            // ensure all other test pass in quirks mode
            testNumericOid();
            testNamesRelaxed();
            testDescription();
            testObsolete();
            testApplies();
            testExtensions();
            testFull();
            testUniqueElements();
            testRequiredElements();
            testOpenldap1();
            testMultiThreaded();
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }
}
