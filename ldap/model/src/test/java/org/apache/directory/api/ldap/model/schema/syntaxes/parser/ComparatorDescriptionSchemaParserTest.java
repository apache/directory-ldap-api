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
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescription;
import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescriptionSchemaParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the ComparatorDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class ComparatorDescriptionSchemaParserTest
{
    /** the parser instance */
    private LdapComparatorDescriptionSchemaParser parser;


    @BeforeEach
    public void setUp() throws Exception
    {
        parser = new LdapComparatorDescriptionSchemaParser();
    }


    @AfterEach
    public void tearDown() throws Exception
    {
        parser = null;
    }


    @Test
    public void testNumericOid() throws ParseException
    {
        SchemaParserTestUtils.testNumericOid( parser, "FQCN org.apache.directory.SimpleComparator" );
    }


    @Test
    public void testDescription() throws ParseException
    {
        SchemaParserTestUtils.testDescription( parser, "1.1", "FQCN org.apache.directory.SimpleComparator" );
    }


    @Test
    public void testFqcn() throws ParseException
    {
        String value = null;
        LdapComparatorDescription ldapComparatorDescription = null;

        // FQCN simple
        value = "( 1.1 FQCN org.apache.directory.SimpleComparator )";
        ldapComparatorDescription = parser.parse( value );
        assertNotNull( ldapComparatorDescription.getFqcn() );
        assertEquals( "org.apache.directory.SimpleComparator", ldapComparatorDescription.getFqcn() );
    }


    @Test
    public void testBytecode() throws ParseException
    {
        String value = null;
        LdapComparatorDescription ldapComparatorDescription = null;

        // FQCN simple p
        value = "( 1.1 FQCN org.apache.directory.SimpleComparator BYTECODE ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789==== )";
        ldapComparatorDescription = parser.parse( value );
        assertNotNull( ldapComparatorDescription.getBytecode() );
        assertEquals( "ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789====", ldapComparatorDescription
            .getBytecode() );

        // FQCN simple, no spaces
        value = "(1.1 FQCNorg.apache.directory.SimpleComparator BYTECODEABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789====)";
        
        try
        { 
            ldapComparatorDescription = parser.parse( value );
            fail( "Exception expected, spaces expected" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // FQCN simple, tabs
        value = "\t(\t1.1\tFQCN\torg.apache.directory.SimpleComparator\tBYTECODE\tABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789====\t)\t";
        ldapComparatorDescription = parser.parse( value );
        assertNotNull( ldapComparatorDescription.getBytecode() );
        assertEquals( "ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789====", ldapComparatorDescription
            .getBytecode() );
    }


    @Test
    public void testExtensions() throws ParseException
    {
        SchemaParserTestUtils.testExtensions( parser, "1.1", "FQCN org.apache.directory.SimpleComparator" );
    }


    @Test
    public void testFull()
    {
        // TODO
    }


    /**
     * Test unique elements.
     */
    @Test
    public void testUniqueElements()
    {
        // TODO
    }


    /**
     * Test required elements.
     */
    @Test
    public void testRequiredElements()
    {
        // TODO
    }


    /**
     * Tests the multithreaded use of a single parser.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testMultiThreaded() throws ParseException
    {
        // TODO
    }


    /**
     * Tests quirks mode.
     * 
     * @throws ParseException If the test failed
     */
    @Test
    public void testQuirksMode() throws ParseException
    {
        SchemaParserTestUtils.testQuirksMode( parser, "FQCN org.apache.directory.SimpleComparator" );

        try
        {
            parser.setQuirksMode( true );

            // ensure all other test pass in quirks mode
            testNumericOid();
            testDescription();
            testFqcn();
            testBytecode();
            testExtensions();
            testFull();
            testUniqueElements();
            testMultiThreaded();
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }
}
