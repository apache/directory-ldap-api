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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.parsers.AbstractSchemaParser;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OpenLdapObjectIdentifierMacro;


/**
 * Utils for schema parser test. Contains tests that are common
 * for many schema parsers like OID, name, desc, extension.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaParserTestUtils
{

    /**
     * Test numericoid
     * 
     * @param parser The schema parser instance
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testNumericOid( AbstractSchemaParser<?> parser, String required ) throws ParseException
    {
        String value = null;
        SchemaObject asd = null;

        // null test
        try
        {
            parser.parse( value );
            fail( "Exception expected, null" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no oid
        value = "( )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, no NUMERICOID" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // simple
        value = "( 0.1.2.3.4.5.6.7.8.9 " + required + " )";
        asd = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", asd.getOid() );

        // simple
        value = "( 1.2.4567.890 " + required + ")";
        asd = parser.parse( value );
        assertEquals( "1.2.4567.890", asd.getOid() );

        // simple with multiple spaces
        value = "(          0.1.2.3.4.5.6.7.8.9         " + required + " )";
        asd = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", asd.getOid() );

        // simple w/o spaces
        value = "(0.1.2.3.4.5.6.7.8.9 " + required + ")";
        asd = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", asd.getOid() );

        // simple with tabs, newline, comment.
        value = "(\t0.1.2.3.4.5.6.7.8.9\n#comment\n" + required + "\r\n)\r";
        asd = parser.parse( value );
        assertEquals( "0.1.2.3.4.5.6.7.8.9", asd.getOid() );

        // quoted OID
        value = "( '0.1.2.3.4.5.6.7.8.9' " + required + " )";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, OID should not be quoted" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // quoted OID in parentheses
        value = "( ('0.1.2.3.4.5.6.7.8.9') " + required + " )";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, OID should not be quoted" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short
        if ( !parser.isQuirksMode() )
        {
            value = "( 1 " + required + " )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NUMERICOID 1" );
            }
            catch ( ParseException pe )
            {
                // expected
            }

            // dot only
            value = "( . " + required + " )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NUMERICOID ." );
            }
            catch ( ParseException pe )
            {
                // expected
            }
            
            // ends with dot
            value = "( 1.1. " + required + " )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NUMERICOID 1.1." );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }

        // multiple not allowed
        value = "( ( 1.2.3 4.5.6 ) " + required + " )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid multiple OIDs not allowed.)" );
        }
        catch ( ParseException pe )
        {
            // excpected
        }
        
        // A descr
        if ( parser.isQuirksMode() )
        {
            value = "( test " + required + ")";
            asd = parser.parse( value );
            assertEquals( "test", asd.getOid() );
    
            // With macro
            OpenLdapObjectIdentifierMacro macro = new OpenLdapObjectIdentifierMacro();
            macro.setName( "macro" );
            macro.setRawOidOrNameSuffix( "0.1" );
            parser.getObjectIdentifiers().put( "macro", macro );
            value = "( macro:2.3.4 " + required + ")";
            asd = parser.parse( value );
            assertEquals( "0.1.2.3.4", asd.getOid() );
        }

        if ( !parser.isQuirksMode() )
        {
            // leading 0 not allowed
            value = "( 01.1 " + required + " )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NUMERICOID 01.1 (leading zero)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }

            // alpha not allowed
            value = "( 1.2.a.4 " + required + " )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid NUMERICOID 1.2.a.4 (alpha not allowed)" );
            }
            catch ( ParseException pe )
            {
                // excpected
            }
        }
    }


    /**
     * Tests NAME and its values
     * 
     * @param parser The schema parser instance
     * @param oid The base OID
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testNamesStrict( AbstractSchemaParser<?> parser, String oid, String required ) throws ParseException
    {
        String value = null;
        SchemaObject asd = null;

        // No name
        value = "( " + oid + " " + required + " )";
        asd = parser.parse( value );
        assertEquals( 0, asd.getNames().size() );

        // A name, no value
        value = "( " + oid + " " + required + " NAME )";
        
        try
        { 
            asd = parser.parse( value );
            fail( "Exception expected, value expected after NAME" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        
        // A name, no space
        value = "( " + oid + " " + required + " NAME'test' )";
        
        try
        { 
            asd = parser.parse( value );
            fail( "Exception expected, value expected after NAME" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // alpha
        value = "( " + oid + " " + required + " NAME 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", asd.getNames().get( 0 ) );

        // alpha-num-hypen
        value = "( " + oid + " " + required
            + " NAME 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", asd.getNames().get( 0 ) );

        // with parentheses
        value = "( " + oid + " " + required + " NAME ( 'a-z-0-9' ) )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getNames().size() );
        assertEquals( "a-z-0-9", asd.getNames().get( 0 ) );

        // Bad value
        value = "(" + oid + " " + required + " NAME 'abc_de')";
        
        try
        {   
            asd = parser.parse( value );
            fail( "Exception expected, invalid chars in name" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // Bad NAME
        value = "(" + oid + " " + required + " NAMEE 'abcde')";
        
        try
        {   
            asd = parser.parse( value );
            fail( "Exception expected, bad NAME" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // with parentheses, without space
        value = "(" + oid + " " + required + " NAME('a-z-0-9'))";
        
        try
        {   
            asd = parser.parse( value );
            fail( "Exception expected, spaces expected after NAME" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // multi with space
        value = " ( " + oid + " " + required + " NAME ( 'test1' 'test2' ) ) ";
        asd = parser.parse( value );
        assertEquals( 2, asd.getNames().size() );
        assertEquals( "test1", asd.getNames().get( 0 ) );
        assertEquals( "test2", asd.getNames().get( 1 ) );

        // multi without space
        value = "(" + oid + " " + required + " NAME('test1''test2''test3'))";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, space expected after NAME" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // multi with many spaces
        value = "(          " + oid + " " + required
            + "          NAME          (          'test1'          'test2'          'test3'          )          )";
        asd = parser.parse( value );
        assertEquals( 3, asd.getNames().size() );
        assertEquals( "test1", asd.getNames().get( 0 ) );
        assertEquals( "test2", asd.getNames().get( 1 ) );
        assertEquals( "test3", asd.getNames().get( 2 ) );

        // multi with tabs, newline, comment, etc.
        value = "(\r\n" + oid + "\r" + required
            + "\nNAME\t(\t\t\t'test1'\t\n\t'test2'\t\r\t'test3'\t\r\n\t)\n#comment\n)";
        asd = parser.parse( value );
        assertEquals( 3, asd.getNames().size() );
        assertEquals( "test1", asd.getNames().get( 0 ) );
        assertEquals( "test2", asd.getNames().get( 1 ) );
        assertEquals( "test3", asd.getNames().get( 2 ) );

        // lowercase NAME
        value = "( " + oid + " " + required + " name 'test' )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getNames().size() );
        assertEquals( "test", asd.getNames().get( 0 ) );

        // unquoted NAME value
        value = "( " + oid + " " + required + " NAME test )";
        
        try
        { 
            asd = parser.parse( value );
            fail( "Exception expected, quoted values expected" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // multi unquoted NAME values
        value = " ( " + oid + " " + required + " NAME (test1 test2) ) ";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, quoted values expected" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // NAM unknown
        value = "( " + oid + " " + required + " NAM 'test' )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid token NAM" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // start with number
        value = "( " + oid + " " + required + " NAME '1test' )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid NAME 1test (starts with number)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // start with hypen
        value = "( " + oid + " " + required + " NAME '-test' )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid NAME -test (starts with hypen)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // invalid character
        value = "( " + oid + " " + required + " NAME 'te_st' )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid NAME te_st (contains invalid character)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // one valid, one invalid
        value = "( " + oid + " " + required + " NAME ( 'test' 'te_st' ) )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid NAME te_st (contains invalid character)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests NAME and its values in relaxed mode
     * 
     * @param parser The schema parser instance
     * @param oid The base OID
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testNamesRelaxed( AbstractSchemaParser<?> parser, String oid, String required ) throws ParseException
    {
        String value = null;
        SchemaObject asd = null;
        boolean isRelaxed = parser.isQuirksMode();
        parser.setQuirksMode( true );

        try
        { 
            // No name
            value = "( " + oid + " " + required + " )";
            asd = parser.parse( value );
            assertEquals( 0, asd.getNames().size() );
    
            // A name, no value
            value = "( " + oid + " " + required + " NAME )";
            
            try
            { 
                asd = parser.parse( value );
                fail( "Exception expected, value expected after NAME" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
            
            // A name, no space
            value = "( " + oid + " " + required + " NAME'test' )";
            
            try
            { 
                asd = parser.parse( value );
                fail( "Exception expected, value expected after NAME" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // alpha
            value = "( " + oid + " " + required + " NAME 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", asd.getNames().get( 0 ) );
    
            // alpha-num-hypen
            value = "( " + oid + " " + required
                + " NAME 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", asd.getNames().get( 0 ) );
    
            // with parentheses
            value = "( " + oid + " " + required + " NAME ( 'a-z-0-9' ) )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "a-z-0-9", asd.getNames().get( 0 ) );
    
            // With extended chars
            value = "(" + oid + " " + required + " NAME 'abc_de')";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "abc_de", asd.getNames().get( 0 ) );
    
            // Bad NAME
            value = "(" + oid + " " + required + " NAMEE 'abcde')";
            
            try
            {   
                asd = parser.parse( value );
                fail( "Exception expected, bad NAME" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // with parentheses, without space
            value = "(" + oid + " " + required + " NAME('a-z-0-9'))";
            
            try
            {   
                asd = parser.parse( value );
                fail( "Exception expected, spaces expected after NAME" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // multi with space
            value = " ( " + oid + " " + required + " NAME ( 'test1' 'test2' ) ) ";
            asd = parser.parse( value );
            assertEquals( 2, asd.getNames().size() );
            assertEquals( "test1", asd.getNames().get( 0 ) );
            assertEquals( "test2", asd.getNames().get( 1 ) );
    
            // multi without space
            value = "(" + oid + " " + required + " NAME('test1''test2''test3'))";
            
            try
            {
                asd = parser.parse( value );
                fail( "Exception expected, space expected after NAME" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // multi with many spaces
            value = "(          " + oid + " " + required
                + "          NAME          (          'test1'          'test2'          'test3'          )          )";
            asd = parser.parse( value );
            assertEquals( 3, asd.getNames().size() );
            assertEquals( "test1", asd.getNames().get( 0 ) );
            assertEquals( "test2", asd.getNames().get( 1 ) );
            assertEquals( "test3", asd.getNames().get( 2 ) );
    
            // multi with tabs, newline, comment, etc.
            value = "(\r\n" + oid + "\r" + required
                + "\nNAME\t(\t\t\t'test1'\t\n\t'test2'\t\r\t'test3'\t\r\n\t)\n#comment\n)";
            asd = parser.parse( value );
            assertEquals( 3, asd.getNames().size() );
            assertEquals( "test1", asd.getNames().get( 0 ) );
            assertEquals( "test2", asd.getNames().get( 1 ) );
            assertEquals( "test3", asd.getNames().get( 2 ) );
    
            // lowercase NAME
            value = "( " + oid + " " + required + " name 'test' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "test", asd.getNames().get( 0 ) );
    
            // unquoted NAME value
            value = "( " + oid + " " + required + " NAME test )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "test", asd.getNames().get( 0 ) );
    
            // multi unquoted NAME values
            value = " ( " + oid + " " + required + " NAME (test1 test2) ) ";
            asd = parser.parse( value );
            assertEquals( 2, asd.getNames().size() );
            assertEquals( "test1", asd.getNames().get( 0 ) );
            assertEquals( "test2", asd.getNames().get( 1 ) );
    
            // NAM unknown
            value = "( " + oid + " " + required + " NAM 'test' )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, invalid token NAM" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
    
            // start with number
            value = "( " + oid + " " + required + " NAME '1test' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "1test", asd.getNames().get( 0 ) );
    
            // start with hypen
            value = "( " + oid + " " + required + " NAME '-test' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "-test", asd.getNames().get( 0 ) );
    
            // invalid character
            value = "( " + oid + " " + required + " NAME 'te_st' )";
            asd = parser.parse( value );
            assertEquals( 1, asd.getNames().size() );
            assertEquals( "te_st", asd.getNames().get( 0 ) );
    
            // one valid, one invalid
            value = "( " + oid + " " + required + " NAME ( 'test' 'te_st' ) )";
            asd = parser.parse( value );
            assertEquals( 2, asd.getNames().size() );
            assertEquals( "test", asd.getNames().get( 0 ) );
            assertEquals( "te_st", asd.getNames().get( 1 ) );
        }
        finally 
        {
            parser.setQuirksMode( isRelaxed );
        }
    }


    /**
     * Tests DESC
     * 
     * @param parser The schema parser instance
     * @param oid The base OID
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testDescription( AbstractSchemaParser<?> parser, String oid, String required )
        throws ParseException
    {
        String value = null;
        SchemaObject asd = null;

        // simple
        value = "(" + oid + " " + required + " DESC 'Description')";
        asd = parser.parse( value );
        assertEquals( "Description", asd.getDescription() );

        // simple with tabs, newline, comment, etc.
        value = "(" + oid + "\n" + required + "\tDESC#comment\n\n\r\n\r\t'Description')";
        asd = parser.parse( value );
        assertEquals( "Description", asd.getDescription() );

        // simple w/o space
        value = "(" + oid + " " + required + " DESC'Description')";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, DESC should have space" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // simple parentheses and quotes
        value = "(" + oid + " " + required + " DESC ('Descripton') )";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, DESC should not have parentheses" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // unicode
        value = "( " + oid + " " + required + " DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' )";
        asd = parser.parse( value );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", asd.getDescription() );

        // escaped characters
        value = "( " + oid + " " + required + " DESC 'test\\5Ctest' )";
        asd = parser.parse( value );
        assertEquals( "test\\test", asd.getDescription() );
        value = "( " + oid + " " + required + " DESC 'test\\5ctest' )";
        asd = parser.parse( value );
        assertEquals( "test\\test", asd.getDescription() );
        value = "( " + oid + " " + required + " DESC 'test\\27test' )";
        asd = parser.parse( value );
        assertEquals( "test'test", asd.getDescription() );
        value = "( " + oid + " " + required + " DESC '\\5C\\27\\5c' )";
        asd = parser.parse( value );
        assertEquals( "\\'\\", asd.getDescription() );
        value = "( " + oid + " " + required + " DESC 'test\\";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, DESC should have simple quote at the end of it\\" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        if ( parser.isQuirksMode() )
        {
            value = "( " + oid + " " + required + " DESC 'test\\23test' )";
            asd = parser.parse( value );
            assertEquals( "test#test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\24test' )";
            asd = parser.parse( value );
            assertEquals( "test$test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\27test' )";
            asd = parser.parse( value );
            assertEquals( "test'test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\5c' )";
            asd = parser.parse( value );
            assertEquals( "test\\", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\' )";
            asd = parser.parse( value );
            assertEquals( "test\\", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\.' )";
            asd = parser.parse( value );
            assertEquals( "test\\.", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\test' )";
            asd = parser.parse( value );
            assertEquals( "test\\test", asd.getDescription() );
        }

        if ( !parser.isQuirksMode() )
        {
            value = "( " + oid + " " + required + " DESC 'test\\23test' )";
            asd = parser.parse( value );
            assertEquals( "test#test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\24test' )";
            asd = parser.parse( value );
            assertEquals( "test$test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\27test' )";
            asd = parser.parse( value );
            assertEquals( "test'test", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\5c' )";
            asd = parser.parse( value );
            assertEquals( "test\\", asd.getDescription() );

            value = "( " + oid + " " + required + " DESC 'test\\' )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, unescaped DESC not allowed.)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }

            value = "( " + oid + " " + required + " DESC 'test\\.' )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, unescaped DESC not allowed.)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }

            value = "( " + oid + " " + required + " DESC 'test\\test' )";
            try
            {
                parser.parse( value );
                fail( "Exception expected, unescaped DESC not allowed.)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }

        // lowercase DESC
        value = "( " + oid + " " + required + " desc 'Descripton' )";
        asd = parser.parse( value );
        assertEquals( "Descripton", asd.getDescription() );

        // empty DESC
        value = "( " + oid + " " + required + " DESC '' )";
        asd = parser.parse( value );
        assertEquals( "", asd.getDescription() );

        // multiple not allowed
        value = "(" + oid + " " + required + " DESC ( 'Descripton1' 'Description 2' )  )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid multiple DESC not allowed.)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Test extensions.
     * 
     * @param parser The schema parser instance
     * @param oid The base OID
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testExtensions( AbstractSchemaParser<?> parser, String oid, String required ) throws ParseException
    {
        String value = null;
        SchemaObject asd = null;

        // no extension
        value = "( " + oid + " " + required + " )";
        asd = parser.parse( value );
        assertEquals( 0, asd.getExtensions().size() );

        // single extension with one value
        value = "( " + oid + " " + required + " X-TEST 'test' )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getExtensions().size() );
        assertNotNull( asd.getExtension( "X-TEST" ) );
        assertEquals( 1, asd.getExtension( "X-TEST" ).size() );
        assertEquals( "test", asd.getExtension( "X-TEST" ).get( 0 ) );

        // single extension with multiple values
        value = "( " + oid + " " + required
            + " X-TEST-ABC ('test1' 'test \u00E4\u00F6\u00FC\u00DF'       'test \u90E8\u9577' ) )";
        asd = parser.parse( value );
        assertEquals( 1, asd.getExtensions().size() );
        assertNotNull( asd.getExtension( "X-TEST-ABC" ) );
        assertEquals( 3, asd.getExtension( "X-TEST-ABC" ).size() );
        assertEquals( "test1", asd.getExtension( "X-TEST-ABC" ).get( 0 ) );
        assertEquals( "test \u00E4\u00F6\u00FC\u00DF", asd.getExtension( "X-TEST-ABC" ).get( 1 ) );
        assertEquals( "test \u90E8\u9577", asd.getExtension( "X-TEST-ABC" ).get( 2 ) );

        // multiple extensions
        value = "(" + oid + " " + required + " X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2'))";
        asd = parser.parse( value );
        assertEquals( 2, asd.getExtensions().size() );
        assertNotNull( asd.getExtension( "X-TEST-a" ) );
        assertEquals( 2, asd.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", asd.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", asd.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( asd.getExtension( "X-TEST-b" ) );
        assertEquals( 2, asd.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", asd.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", asd.getExtension( "X-TEST-b" ).get( 1 ) );

        // multiple extensions, no spaces
        value = "(" + oid + " " + required + " X-TEST-a('test1-1''test1-2')X-TEST-b('test2-1''test2-2'))";
        
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, EXTENSION should have spaces" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // multiple extensions, tabs, newline, comments
        value = "(" + oid + "\n#comment\n" + required
            + "\nX-TEST-a\n(\t'test1-1'\t\n'test1-2'\n\r)\tX-TEST-b\n(\n'test2-1'\t'test2-2'\t)\r)";
        asd = parser.parse( value );
        assertEquals( 2, asd.getExtensions().size() );
        assertNotNull( asd.getExtension( "X-TEST-a" ) );
        assertEquals( 2, asd.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", asd.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", asd.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( asd.getExtension( "X-TEST-b" ) );
        assertEquals( 2, asd.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", asd.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", asd.getExtension( "X-TEST-b" ).get( 1 ) );

        // some more complicated
        value = "(" + oid + " " + required
            + " X-_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ('\\5C\\27\\5c'))";
        asd = parser.parse( value );
        assertEquals( 1, asd.getExtensions().size() );
        assertNotNull( asd.getExtension( "X-_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ) );
        assertEquals( 1, asd.getExtension( "X-_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" )
            .size() );
        assertEquals( "\\'\\", asd.getExtension(
            "X-_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ).get( 0 ) );

        // invalid extension, no number allowed
        value = "( " + oid + " " + required + " X-TEST1 'test' )";
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, invalid extension X-TEST1 (no number allowed)" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }

    }


    /**
     * Tests OBSOLETE
     * 
     * @param parser The schema parser instance
     * @param oid The base OID
     * @param required The required part
     * @throws ParseException If the test failed
     */
    public static void testObsolete( AbstractSchemaParser<?> parser, String oid, String required ) throws ParseException
    {
        String value = null;
        SchemaObject asd = null;

        // not obsolete
        value = "( " + oid + " " + required + " )";
        asd = parser.parse( value );
        assertFalse( asd.isObsolete() );

        // not obsolete
        value = "( " + oid + " " + required + " NAME 'test' DESC 'Description' )";
        asd = parser.parse( value );
        assertFalse( asd.isObsolete() );

        // obsolete
        value = "(" + oid + " " + required + " NAME 'test' DESC 'Description' OBSOLETE)";
        asd = parser.parse( value );
        assertTrue( asd.isObsolete() );

        // obsolete
        value = "(" + oid + " " + required + " OBSOLETE)";
        asd = parser.parse( value );
        assertTrue( asd.isObsolete() );

        // lowercased obsolete
        value = "(" + oid + " " + required + " obsolete)";
        asd = parser.parse( value );
        assertTrue( asd.isObsolete() );

        // invalid
        value = "(" + oid + " " + required + " NAME 'test' DESC 'Descripton' OBSOLET )";
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, invalid OBSOLETE value" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // trailing value not allowed
        value = "(" + oid + " " + required + " NAME 'test' DESC 'Descripton' OBSOLETE 'true' )";
        try
        {
            asd = parser.parse( value );
            fail( "Exception expected, trailing value ('true') now allowed" );
        }
        catch ( ParseException pe )
        {
            assertTrue( true );
        }
    }


    /**
     * Tests for unique elements.
     * 
     * @param parser The schema parser
     * @param testValues The values to test
     */
    public static void testUnique( AbstractSchemaParser<?> parser, String[] testValues )
    {
        for ( int i = 0; i < testValues.length; i++ )
        {
            String testValue = testValues[i];
            try
            {
                parser.parse( testValue );
                fail( "Exception expected, element appears twice in " + testValue );
            }
            catch ( ParseException pe )
            {
                assertTrue( true );
            }
        }

    }


    /**
     * Tests the multithreaded use of a single parser.
     * 
     * @param parser The schema parser
     * @param testValues The values to test
     */
    public static void testMultiThreaded( AbstractSchemaParser<?> parser, String[] testValues )
    {
        final boolean[] isSuccessMultithreaded = new boolean[1];
        isSuccessMultithreaded[0] = true;

        // start up and track all threads (40 threads)
        List<Thread> threads = new ArrayList<Thread>();
        for ( int ii = 0; ii < 10; ii++ )
        {
            for ( int i = 0; i < testValues.length; i++ )
            {
                Thread t = new Thread( new ParseSpecification( parser, testValues[i], isSuccessMultithreaded ) );
                threads.add( t );
                t.start();
            }
        }

        // wait until all threads have died
        boolean hasLiveThreads = false;
        do
        {
            hasLiveThreads = false;

            for ( int ii = 0; ii < threads.size(); ii++ )
            {
                Thread t = threads.get( ii );
                hasLiveThreads = hasLiveThreads || t.isAlive();
            }
        }
        while ( hasLiveThreads );

        // check that no one thread failed to parse and generate a SS object
        assertTrue( isSuccessMultithreaded[0] );

    }


    /**
     * Tests quirks mode.
     * 
     * @param parser The schema parser
     * @param required The resuired part
     * @throws ParseException If the test failed
     */
    public static void testQuirksMode( AbstractSchemaParser<?> parser, String required ) throws ParseException
    {
        try
        {
            String value = null;
            SchemaObject asd = null;

            parser.setQuirksMode( true );

            // alphanum OID
            value = "( abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789 " + required + " )";
            asd = parser.parse( value );
            assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", asd
                .getOid() );

            // start with hypen
            value = "( -oid " + required + " )";
            asd = parser.parse( value );
            assertEquals( "-oid", asd.getOid() );

            // start with number
            value = "( 1oid " + required + " )";
            asd = parser.parse( value );
            assertEquals( "1oid", asd.getOid() );

            // start with dot
            value = "( .oid " + required + " )";
            asd = parser.parse( value );
            assertEquals( ".oid", asd.getOid() );
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }

    static class ParseSpecification implements Runnable
    {
        private final AbstractSchemaParser<?> parser;
        private final String value;
        private final boolean[] isSuccessMultithreaded;

        private SchemaObject result;


        public ParseSpecification( AbstractSchemaParser<?> parser, String value, boolean[] isSuccessMultithreaded )
        {
            this.parser = parser;
            this.value = value;
            this.isSuccessMultithreaded = isSuccessMultithreaded;
        }


        public void run()
        {
            try
            {
                result = parser.parse( value );
            }
            catch ( ParseException e )
            {
                e.printStackTrace();
            }

            isSuccessMultithreaded[0] = isSuccessMultithreaded[0] && ( result != null );
        }
    }
}
