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

import javax.naming.NamingException;

import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.parsers.MatchingRuleDescriptionSchemaParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the MatchingRuleDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class MatchingRuleDescriptionSchemaParserTest
{
    /** the parser instance */
    private MatchingRuleDescriptionSchemaParser parser;


    @BeforeEach
    public void setUp() throws Exception
    {
        parser = new MatchingRuleDescriptionSchemaParser();
    }


    @AfterEach
    public void tearDown() throws Exception
    {
        parser = null;
    }


    @Test
    public void testNumericOid() throws ParseException
    {
        SchemaParserTestUtils.testNumericOid( parser, "SYNTAX 1.1" );
    }


    @Test
    public void testNamesRelaxed() throws ParseException
    {
        SchemaParserTestUtils.testNamesRelaxed( parser, "1.1", "SYNTAX 1.1" );
    }


    @Test
    public void testNamesStrict() throws ParseException
    {
        SchemaParserTestUtils.testNamesStrict( parser, "1.1", "SYNTAX 1.1" );
    }


    @Test
    public void testDescription() throws ParseException
    {
        SchemaParserTestUtils.testDescription( parser, "1.1", "SYNTAX 1.1" );
    }


    @Test
    public void testObsolete() throws ParseException
    {
        SchemaParserTestUtils.testObsolete( parser, "1.1", "SYNTAX 1.1" );
    }


    @Test
    public void testSyntaxStrict() throws ParseException, NamingException
    {
        String value = null;
        MatchingRule matchingRule = null;

        // simple
        value = "( 1.1 SYNTAX 0.1.2.3.4.5.6.7.8.9 )";
        matchingRule = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRule.getSyntaxOid() );

        // simple
        value = "(1.1 SYNTAX 1.2.456.789.0)";
        matchingRule = parser.parse( value );
        assertEquals( "1.2.456.789.0", matchingRule.getSyntaxOid() );

        // simple with spaces
        value = "( 1.1    SYNTAX    0.1.2.3.4.5.6.7.8.9    )";
        matchingRule = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRule.getSyntaxOid() );

        // quoted value in parentheses
        value = "( 1.1    SYNTAX ('0.1.2.3.4.5.6.7.8.9')    )";
        
        try
        {
            matchingRule = parser.parse( value );
            fail( "Exception expected, parentheses not allowed" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }

        // SYNTAX must only appear once
        value = "( 1.1 SYNTAX 2.2 SYNTAX 3.3 )";
        try
        {
            matchingRule = parser.parse( value );
            fail( "Exception expected, SYNTAX appears twice" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }

        // non-numeric not allowed
        value = "( test )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, SYNTAX is require" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // SYNTAX is required
        value = "( 1.1 )";
        try
        {
            matchingRule = parser.parse( value );
            fail( "Exception expected, SYNTAX is required" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    @Test
    public void testSyntaxRelaxed() throws ParseException, NamingException
    {
        String value = null;
        MatchingRule matchingRule = null;

        // simple
        value = "( 1.1 SYNTAX 0.1.2.3.4.5.6.7.8.9 )";
        matchingRule = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRule.getSyntaxOid() );

        // simple
        value = "(1.1 SYNTAX 1.2.456.789.0)";
        matchingRule = parser.parse( value );
        assertEquals( "1.2.456.789.0", matchingRule.getSyntaxOid() );

        // simple with spaces
        value = "( 1.1    SYNTAX    0.1.2.3.4.5.6.7.8.9    )";
        matchingRule = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRule.getSyntaxOid() );

        // quoted value in parentheses
        value = "( 1.1    SYNTAX ('0.1.2.3.4.5.6.7.8.9')    )";
        
        try
        {
            matchingRule = parser.parse( value );
            fail( "Exception expected, parentheses not allowed" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }

        // SYNTAX must only appear once
        value = "( 1.1 SYNTAX 2.2 SYNTAX 3.3 )";
        try
        {
            matchingRule = parser.parse( value );
            fail( "Exception expected, SYNTAX appears twice" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testExtensions() throws ParseException
    {
        SchemaParserTestUtils.testExtensions( parser, "1.1", "SYNTAX 1.1" );
    }


    @Test
    public void testFull() throws ParseException, NamingException
    {
        String value = null;
        MatchingRule matchingRule = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE SYNTAX 0.1.2.3.4.5.6.7.8.9 X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )";
        matchingRule = parser.parse( value );

        assertEquals( "1.2.3.4.5.6.7.8.9.0", matchingRule.getOid() );
        assertEquals( 2, matchingRule.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789",
            matchingRule.getNames().get( 0 ) );
        assertEquals( "test", matchingRule.getNames().get( 1 ) );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", matchingRule.getDescription() );
        assertTrue( matchingRule.isObsolete() );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", matchingRule.getSyntaxOid() );
        assertEquals( 2, matchingRule.getExtensions().size() );
        assertNotNull( matchingRule.getExtension( "X-TEST-a" ) );
        assertEquals( 2, matchingRule.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", matchingRule.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", matchingRule.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( matchingRule.getExtension( "X-TEST-b" ) );
        assertEquals( 2, matchingRule.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", matchingRule.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", matchingRule.getExtension( "X-TEST-b" ).get( 1 ) );
    }


    /**
     * Test unique elements.
     */
    @Test
    public void testUniqueElements()
    {
        String[] testValues = new String[]
            { "( 1.1 SYNTAX 1.1 NAME 'test1' NAME 'test2' )", "( 1.1 SYNTAX 1.1 DESC 'test1' DESC 'test2' )",
                "( 1.1 SYNTAX 1.1 OBSOLETE OBSOLETE )", "( 1.1 SYNTAX 1.1 SYNTAX 2.2 SYNTAX 3.3 )",
                "( 1.1 SYNTAX 1.1 X-TEST 'test1' X-TEST 'test2' )" };
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
        MatchingRule matchingRule = null;

        value = "( 1.2.3.4.5.6.7.8.9.0 SYNTAX 1.1 )";
        matchingRule = parser.parse( value );
        assertNotNull( matchingRule.getSyntaxOid() );

        if ( !parser.isQuirksMode() )
        {
            value = "( 1.2.3.4.5.6.7.8.9.0 )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, SYNTAX is required" );
            }
            catch ( ParseException pe )
            {
                assertTrue( true );
            }
        }
    }


    ////////////////////////////////////////////////////////////////
    //         Some real-world matching rule descriptons          //
    ////////////////////////////////////////////////////////////////

    @Test
    public void testRfc1() throws ParseException
    {
        String value = "( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
        MatchingRule matchingRule = parser.parse( value );

        assertEquals( "2.5.13.5", matchingRule.getOid() );
        assertEquals( 1, matchingRule.getNames().size() );
        assertEquals( "caseExactMatch", matchingRule.getNames().get( 0 ) );
        assertNull( matchingRule.getDescription() );
        assertFalse( matchingRule.isObsolete() );
        assertEquals( "1.3.6.1.4.1.1466.115.121.1.15", matchingRule.getSyntaxOid() );
        assertEquals( 0, matchingRule.getExtensions().size() );
    }


    @Test
    public void testSun1() throws ParseException
    {
        String value = "( 2.5.13.5 NAME 'caseExactMatch' DESC 'Case Exact Matching on Directory String [defined in X.520]' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
        MatchingRule matchingRule = parser.parse( value );

        assertEquals( "2.5.13.5", matchingRule.getOid() );
        assertEquals( 1, matchingRule.getNames().size() );
        assertEquals( "caseExactMatch", matchingRule.getNames().get( 0 ) );
        assertEquals( "Case Exact Matching on Directory String [defined in X.520]", matchingRule.getDescription() );
        assertFalse( matchingRule.isObsolete() );
        assertEquals( "1.3.6.1.4.1.1466.115.121.1.15", matchingRule.getSyntaxOid() );
        assertEquals( 0, matchingRule.getExtensions().size() );
    }


    /**
     * This is a real matching rule from Sun Directory 5.2. It has an invalid 
     * syntax, no DOTs allowed in NAME value. 
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testSun2() throws ParseException
    {
        String value = "( 1.3.6.1.4.1.42.2.27.9.4.34.3.6 NAME 'caseExactSubstringMatch-2.16.840.1.113730.3.3.2.11.3' DESC 'en' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
        if ( !parser.isQuirksMode() )
        {
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NAME value 'caseExactSubstringMatch-2.16.840.1.113730.3.3.2.11.3' (contains DOTs)" );
            }
            catch ( ParseException pe )
            {
                assertTrue( true );
            }
        }
        else
        {
            MatchingRule matchingRule = parser.parse( value );
            assertEquals( "1.3.6.1.4.1.42.2.27.9.4.34.3.6", matchingRule.getOid() );
            assertEquals( 1, matchingRule.getNames().size() );
            assertEquals( "caseExactSubstringMatch-2.16.840.1.113730.3.3.2.11.3", matchingRule.getNames().get( 0 ) );
            assertEquals( "en", matchingRule.getDescription() );
            assertFalse( matchingRule.isObsolete() );
            assertEquals( "1.3.6.1.4.1.1466.115.121.1.15", matchingRule.getSyntaxOid() );
            assertEquals( 0, matchingRule.getExtensions().size() );
        }
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
                "( 1.1 SYNTAX 1.1 )",
                "( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                "( 2.5.13.5 NAME 'caseExactMatch' DESC 'Case Exact Matching on Directory String [defined in X.520]' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                "( 1.2.3.4.5.6.7.8.9.0 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE SYNTAX 0.1.2.3.4.5.6.7.8.9 X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )" };
        SchemaParserTestUtils.testMultiThreaded( parser, testValues );
    }


    /**
     * Tests quirks mode.
     * 
     * @throws ParseException If the test failed
     * @throws NamingException If the test failed
     */
    @Test
    public void testQuirksMode() throws ParseException, NamingException
    {
        SchemaParserTestUtils.testQuirksMode( parser, "SYNTAX 1.1" );

        try
        {
            parser.setQuirksMode( true );

            // ensure all other test pass in quirks mode
            testNumericOid();
            testNamesRelaxed();
            testDescription();
            testObsolete();
            testSyntaxRelaxed();
            testExtensions();
            testFull();
            testUniqueElements();
            testRequiredElements();
            testRfc1();
            testSun1();
            testSun2();
            testMultiThreaded();
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }

}
