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
 */
package org.apache.directory.api.ldap.model.schema.normalizers;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.util.Strings;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * Test the normalizer class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DeepTrimToLowerNormalizerTest
{
    @Test
    public void testDeepTrimToLowerNormalizerNull() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertNull( normalizer.normalize( ( String ) null ) );
    }


    @Test
    public void testDeepTrimToLowerNormalizerEmpty() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( "  ", normalizer.normalize( "" ) );
    }


    @Test
    public void testDeepTrimToLowerNormalizerOneSpace() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( "  ", normalizer.normalize( " " ) );
    }


    @Test
    public void testDeepTrimToLowerNormalizerTwoSpaces() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( "  ", normalizer.normalize( "  " ) );
    }


    @Test
    public void testDeepTrimToLowerNormalizerNSpaces() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( "  ", normalizer.normalize( "      " ) );
    }


    @Test
    public void testInsignifiantSpacesStringOneChar() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( " a ", normalizer.normalize( "a" ) );
    }


    @Test
    public void testInsignifiantSpacesStringTwoChars() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( " aa ", normalizer.normalize( "aa" ) );
    }


    @Test
    public void testInsignifiantSpacesStringNChars() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( " aaaaa ", normalizer.normalize( "aaaaa" ) );
    }


    @Test
    public void testInsignifiantSpacesStringOneCombining() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        char[] chars = new char[]
            { 'e', 0x0301 };
        char[] expected = new char[]
            { ' ', '\u00E9', ' ' };
        
        String expectedStr = new String( expected );
        String charsStr = new String( chars );
        assertEquals( expectedStr, normalizer.normalize( charsStr ) );
    }


    @Test
    public void testInsignifiantSpacesStringNCombining() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        char[] chars = new char[]
            { 'e', 0x0301, ' ', 'a', 0x0300, 'i', 0x0302 };
        char[] expected = new char[]
            { ' ', '\u00E9', ' ', ' ', '\u00E0', '\u00EE', ' ' };
        assertEquals( new String( expected ), normalizer.normalize( new String( chars ) ) );
    }


    @Test
    public void testInsignifiantSpacesStringCharsSpaces() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( " a ", normalizer.normalize( " a" ) );
        assertEquals( " a ", normalizer.normalize( "a " ) );
        assertEquals( " a ", normalizer.normalize( " a " ) );
        assertEquals( " a  a ", normalizer.normalize( "a a" ) );
        assertEquals( " a  a ", normalizer.normalize( " a a" ) );
        assertEquals( " a  a ", normalizer.normalize( "a a " ) );
        assertEquals( " a  a ", normalizer.normalize( "a  a" ) );
        assertEquals( " a  a ", normalizer.normalize( " a   a " ) );
        assertEquals( " aaa  aaa  aaa ", normalizer.normalize( "  aaa   aaa   aaa  " ) );
    }


    @Test
    public void testNormalizeCharsCombiningSpaces() throws LdapException
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        char[] chars = new char[]
            { 'a', 'm', ' ', 'e', 0x0301, 'l', 'i', 'e' };
        char[] expected = new char[]
            { ' ', 'a', 'm', ' ', ' ', '\u00e9', 'l', 'i' , 'e', ' ' };
        String expectedStr = new String( expected );
        String charsStr = new String( chars );
        assertEquals( expectedStr, normalizer.normalize( charsStr ) );
    }


    @Test
    public void testNormalizeString() throws Exception
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        assertEquals( " abcd ", normalizer.normalize( "abcd" ) );
    }


    @Test
    public void testMapToSpace() throws Exception
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        char[] chars = new char[]
            { 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0085, 0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
                0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F };
        assertEquals( "  ", normalizer.normalize( new String( chars ) ) );
    }


    @Test
    public void testNormalizeIgnore() throws Exception
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer( "1.1.1" );
        char[] chars = new char[58];

        int pos = 0;

        for ( char c = 0x0000; c < 0x0008; c++ )
        {
            chars[pos++] = c;
        }

        for ( char c = 0x000E; c < 0x001F; c++ )
        {
            chars[pos++] = c;
        }

        for ( char c = 0x007F; c < 0x0084; c++ )
        {
            chars[pos++] = c;
        }

        for ( char c = 0x0086; c < 0x009F; c++ )
        {
            chars[pos++] = c;
        }

        chars[pos++] = 0x00AD;

        assertEquals( "  ", normalizer.normalize( new String( chars ) ) );
    }

    
    @Test
    @Ignore
    public void testSpeed() throws Exception
    {
        Normalizer normalizer = new DeepTrimToLowerNormalizer();
        
        String t = "xs crvtbynU  Jikl7897A90";
                
        normalizer.normalize( t );

        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < 100000000; i++ )
        {
            normalizer.normalize( t );
        }
        
        long t1 = System.currentTimeMillis();
        
        System.out.println( t1 - t0 );

        Strings.deepTrimToLower( t );

        t0 = System.currentTimeMillis();

        for ( int i = 0; i < 100000000; i++ )
        {
            Strings.deepTrimToLower( t );
        }
        
        t1 = System.currentTimeMillis();
        
        System.out.println( t1 - t0 );
    }
}