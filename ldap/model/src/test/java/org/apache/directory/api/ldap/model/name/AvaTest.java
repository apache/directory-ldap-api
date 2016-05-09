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
package org.apache.directory.api.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Ava;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the class AttributeTypeAndValue
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AvaTest
{
    /** A null schemaManager used in tests */
    SchemaManager schemaManager = null;


    /**
     * Test a null AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueNull()
    {
        Ava atav = new Ava();
        assertEquals( "", atav.toString() );
        assertEquals( "", atav.getName() );
    }


    /**
     * Test a null type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueNullType() throws LdapException
    {
        try
        {
            new Ava( schemaManager, null, ( String ) null );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }

    }


    /**
     * Test an invalid type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueInvalidType() throws LdapException
    {
        try
        {
            new Ava( schemaManager, "  ", ( String ) null );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * Test a valid type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueValidType() throws LdapException
    {
        Ava atav = new Ava( schemaManager, "DC", ( String ) null );
        assertEquals( "DC=", atav.toString() );
        assertEquals( "DC=", atav.getName() );

        atav = new Ava( schemaManager, "  DC  ", ( String ) null );
        assertEquals( "  DC  =", atav.toString() );
        assertEquals( "  DC  =", atav.getName() );

        try
        {
            atav = new Ava( schemaManager, null, ( String ) null );
            fail();
        }
        catch ( LdapInvalidDnException lide )
        {
            assertTrue( true );
        }
    }


    /**
     * test an empty AttributeTypeAndValue
     */
    @Test
    public void testLdapRDNEmpty()
    {
        try
        {
            new Ava( schemaManager, "", "" );
            fail( "Should not occurs ... " );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * test a simple AttributeTypeAndValue : a = b
     */
    @Test
    public void testLdapRDNSimple() throws LdapException
    {
        Ava atav = new Ava( schemaManager, "a", "b" );
        assertEquals( "a=b", atav.toString() );
        assertEquals( "a=b", atav.getName() );
    }


    /**
     * Compares two equals atavs
     */
    @Test
    public void testEqualsAttributeEquals() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "a", "b" );
        Ava atav2 = new Ava( schemaManager, "a", "b" );

        assertTrue( atav1.equals( atav2 ) );
    }


    /**
     * Compares two equals atavs but with a type in different case
     */
    @Test
    public void testEqualsAttributeIdSameCase() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "a", "b" );
        Ava atav2 = new Ava( schemaManager, "A", "b" );

        assertTrue( atav1.equals( atav2 ) );
    }


    /**
     * Compare two atavs : the first one is superior because its type is
     * superior
     */
    @Test
    public void testEqualsAtav1TypeSuperior() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "b", "b" );

        Ava atav2 = new Ava( schemaManager, "a", "b" );

        assertFalse( atav1.equals( atav2 ) );
    }


    /**
     * Compare two atavs : the second one is superior because its type is
     * superior
     */
    @Test
    public void testEqualsAtav2TypeSuperior() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "a", "b" );
        Ava atav2 = new Ava( schemaManager, "b", "b" );

        assertFalse( atav1.equals( atav2 ) );
    }


    /**
     * Compare two atavs : the first one is superior because its type is
     * superior
     */
    @Test
    public void testEqualsAtav1ValueSuperior() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "a", "b" );
        Ava atav2 = new Ava( schemaManager, "a", "a" );

        assertFalse( atav1.equals( atav2 ) );
    }


    /**
     * Compare two atavs : the second one is superior because its type is
     * superior
     */
    @Test
    public void testEqualsAtav2ValueSuperior() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "a", "a" );
        Ava atav2 = new Ava( schemaManager, "a", "b" );

        assertFalse( atav1.equals( atav2 ) );
    }


    @Test
    public void testNormalize() throws LdapException
    {
        Ava atav = new Ava( schemaManager, " A ", "a" );

        assertEquals( " A =a", atav.getName() );

    }


    @Test
    public void testAvaSimpleNorm() throws LdapException
    {
        Ava atav = new Ava( schemaManager, " CommonName ", " This is    a TEST " );
        assertEquals( " CommonName =\\ This is    a TEST\\ ", atav.toString() );
        assertEquals( " CommonName =\\ This is    a TEST\\ ", atav.getName() );
    }


    @Test
    public void testAvaEscapedLeadChar() throws LdapException
    {
        // Lead char : 0x00
        Ava atav = new Ava( schemaManager, "cn", new byte[] { 0x00 } );
        assertEquals( "cn=\\00", atav.getName() );
        assertEquals( "cn=\\00", atav.getEscaped() );

        // Lead char : 0x20
        atav = new Ava( schemaManager, "cn", new byte[] { 0x20 } );
        assertEquals( "cn=\\ ", atav.getName() );
        assertEquals( "cn=\\ ", atav.getEscaped() );

        // Lead char : '#'
        atav = new Ava( schemaManager, "cn", new byte[] { '#' } );
        assertEquals( "cn=\\#", atav.getName() );
        assertEquals( "cn=\\#", atav.getEscaped() );

        // Lead char : ','
        atav = new Ava( schemaManager, "cn", new byte[] { ',' } );
        assertEquals( "cn=\\,", atav.getName() );
        assertEquals( "cn=\\,", atav.getEscaped() );

        // Lead char : ';'
        atav = new Ava( schemaManager, "cn", new byte[] { ';' } );
        assertEquals( "cn=\\;", atav.getName() );
        assertEquals( "cn=\\;", atav.getEscaped() );

        // Lead char : '+'
        atav = new Ava( schemaManager, "cn", new byte[] { '+' } );
        assertEquals( "cn=\\+", atav.getName() );
        assertEquals( "cn=\\+", atav.getEscaped() );

        // Lead char : '"'
        atav = new Ava( schemaManager, "cn", new byte[] { '"' } );
        assertEquals( "cn=\\\"", atav.getName() );
        assertEquals( "cn=\\\"", atav.getEscaped() );

        // Lead char : '<'
        atav = new Ava( schemaManager, "cn", new byte[] { '<' } );
        assertEquals( "cn=\\<", atav.getName() );
        assertEquals( "cn=\\<", atav.getEscaped() );

        // Lead char : '>'
        atav = new Ava( schemaManager, "cn", new byte[] { '>' } );
        assertEquals( "cn=\\>", atav.getName() );
        assertEquals( "cn=\\>", atav.getEscaped() );

        // Lead char : '\'
        atav = new Ava( schemaManager, "cn", new byte[] { '\\' } );
        assertEquals( "cn=\\\\", atav.getName() );
        assertEquals( "cn=\\\\", atav.getEscaped() );
    }


    @Test
    public void testAvaEscapedTrailChar() throws LdapException
    {
        // Trail char : 0x00
        Ava atav = new Ava( schemaManager, "cn", new byte[] { 'a', 0x00 } );
        assertEquals( "cn=a\\00", atav.getName() );
        assertEquals( "cn=a\\00", atav.getEscaped() );

        // Trail char : 0x20
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', 0x20 } );
        assertEquals( "cn=a\\ ", atav.getName() );
        assertEquals( "cn=a\\ ", atav.getEscaped() );

        // Trail char : '#' (it should not be escaped)
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '#' } );
        assertEquals( "cn=a#", atav.getName() );
        assertEquals( "cn=a#", atav.getEscaped() );

        // Trail char : ','
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', ',' } );
        assertEquals( "cn=a\\,", atav.getName() );
        assertEquals( "cn=a\\,", atav.getEscaped() );

        // Trail char : ';'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', ';' } );
        assertEquals( "cn=a\\;", atav.getName() );
        assertEquals( "cn=a\\;", atav.getEscaped() );

        // Trail char : '+'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '+' } );
        assertEquals( "cn=a\\+", atav.getName() );
        assertEquals( "cn=a\\+", atav.getEscaped() );

        // Trail char : '"'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '"' } );
        assertEquals( "cn=a\\\"", atav.getName() );
        assertEquals( "cn=a\\\"", atav.getEscaped() );

        // Trail char : '<'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '<' } );
        assertEquals( "cn=a\\<", atav.getName() );
        assertEquals( "cn=a\\<", atav.getEscaped() );

        // Trail char : '>'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '>' } );
        assertEquals( "cn=a\\>", atav.getName() );
        assertEquals( "cn=a\\>", atav.getEscaped() );

        // Trail char : '\'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '\\' } );
        assertEquals( "cn=a\\\\", atav.getName() );
        assertEquals( "cn=a\\\\", atav.getEscaped() );
    }


    @Test
    public void testAvaEscapedMiddleChar() throws LdapException
    {
        // Trail char : 0x00
        Ava atav = new Ava( schemaManager, "cn", new byte[] { 'a', 0x00, 'b' } );
        assertEquals( "cn=a\\00b", atav.getName() );
        assertEquals( "cn=a\\00b", atav.getEscaped() );

        // Trail char : 0x20 (it should not be escaped)
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', 0x20, 'b' } );
        assertEquals( "cn=a b", atav.getName() );
        assertEquals( "cn=a b", atav.getEscaped() );

        // Trail char : '#' (it should not be escaped)
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '#', 'b' } );
        assertEquals( "cn=a#b", atav.getName() );
        assertEquals( "cn=a#b", atav.getEscaped() );

        // Trail char : ','
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', ',', 'b' } );
        assertEquals( "cn=a\\,b", atav.getName() );
        assertEquals( "cn=a\\,b", atav.getEscaped() );

        // Trail char : ';'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', ';', 'b' } );
        assertEquals( "cn=a\\;b", atav.getName() );
        assertEquals( "cn=a\\;b", atav.getEscaped() );

        // Trail char : '+'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '+', 'b' } );
        assertEquals( "cn=a\\+b", atav.getName() );
        assertEquals( "cn=a\\+b", atav.getEscaped() );

        // Trail char : '"'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '"', 'b' } );
        assertEquals( "cn=a\\\"b", atav.getName() );
        assertEquals( "cn=a\\\"b", atav.getEscaped() );

        // Trail char : '<'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '<', 'b' } );
        assertEquals( "cn=a\\<b", atav.getName() );
        assertEquals( "cn=a\\<b", atav.getEscaped() );

        // Trail char : '>'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '>', 'b' } );
        assertEquals( "cn=a\\>b", atav.getName() );
        assertEquals( "cn=a\\>b", atav.getEscaped() );

        // Trail char : '\'
        atav = new Ava( schemaManager, "cn", new byte[] { 'a', '\\', 'b' } );
        assertEquals( "cn=a\\\\b", atav.getName() );
        assertEquals( "cn=a\\\\b", atav.getEscaped() );
    }


    @Test
    public void testAvaUTF2() throws LdapException
    {
        // The '¡' char (U+00A1)
        Ava atav = new Ava( schemaManager, "cn", new byte[] { ( byte ) 0xC2, ( byte ) 0xA1 } );
        assertEquals( "cn=\u00A1", atav.toString() );
        assertEquals( "cn=\u00A1", atav.getName() );

        // Some octets, which are not UTF-2
        atav = new Ava( schemaManager, "cn", new byte[] { ( byte ) 0xFE, ( byte ) 0xC2, ( byte ) 0xC0, ( byte ) 0xC2 } );
        assertEquals( "cn=\\FE\\C2\\C0\\C2", atav.getName() );
        assertEquals( "cn=\\FE\\C2\\C0\\C2", atav.getEscaped() );
    }


    @Test
    public void testAvaUTF3() throws LdapException
    {
        // UTF-3 starting with 0xE0
        // 0x090E unicode is 0xE0 0xA4 0x8E UTF-8, ie DEVANAGARI LETTER SHORT E ('ऎ')
        Ava atav = new Ava( schemaManager, "cn", new byte[]{ ( byte ) 0xE0, ( byte ) 0xA4, ( byte ) 0x8E } );
        assertEquals( "cn=\u090E", atav.getName() );
        assertEquals("cn=\u090E", atav.getEscaped() );

        // UTF-3 between 0xE1 and 0xEC
        // 0x1000 unicode is 0xE1 0x80 0x80 UTF-8, ie MYANMAR LETTER KA ('က')
        atav = new Ava( schemaManager, "cn", new byte[]{ ( byte ) 0xE1, ( byte ) 0x80, ( byte ) 0x80 } );
        assertEquals( "cn=\u1000", atav.getName() );
        assertEquals("cn=\u1000", atav.getEscaped() );

        // 0xCFFF unicode is 0xEC 0xBF 0xBF UTF-8 ('쿿')
        atav = new Ava( schemaManager, "cn", new byte[]{ ( byte ) 0xEC, ( byte ) 0xBF, ( byte ) 0xBF } );
        assertEquals( "cn=\uCFFF", atav.getName() );
        assertEquals("cn=\uCFFF", atav.getEscaped() );

        // UTF-3 starting with 0xED
        // 0xD000 unicode is 0xED 0x80 0x80 UTF-8 ('퀀')
        atav = new Ava( schemaManager, "cn", new byte[]{ ( byte ) 0xED, ( byte ) 0x80, ( byte ) 0x80 } );
        assertEquals( "cn=\uD000", atav.getName() );
        assertEquals("cn=\uD000", atav.getEscaped() );

        // UTF-3 starting with 0xEE or 0xEF
        // 0xFC00 unicode is 0xEF 0xB0 0x80 UTF-8, ie ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH JEEM ISOLATED FORM ('ﰀ')
        atav = new Ava( schemaManager, "cn", new byte[]{ ( byte ) 0xEF, ( byte ) 0xB0, ( byte ) 0x80 } );
        assertEquals( "cn=\uFC00", atav.getName() );
        assertEquals("cn=\uFC00", atav.getEscaped() );

        // Some octets, which are not UTF-3
        atav = new Ava( schemaManager, "cn", new byte[] { ( byte ) 0xE0, 0x61, ( byte ) 0xE0, ( byte ) 0xA0, 0x61 } );
        assertEquals( "cn=\\E0a\\E0\\A0a", atav.getName() );
        assertEquals( "cn=\\E0a\\E0\\A0a", atav.getEscaped() );

        // Some octets, which are not UTF-3
        atav = new Ava( schemaManager, "cn", new byte[] { ( byte ) 0xE0, ( byte ) 0xA0 } );
        assertEquals( "cn=\\E0\\A0", atav.getName() );
        assertEquals( "cn=\\E0\\A0", atav.getEscaped() );
    }
}
