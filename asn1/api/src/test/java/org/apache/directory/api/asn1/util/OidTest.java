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
package org.apache.directory.api.asn1.util;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.directory.api.asn1.DecoderException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class OidTest
{
    private static final Logger logger = LoggerFactory.getLogger( OidTest.class );


    @Test
    public void speed()
    {
        byte[] bytes = new byte[]
            { 0x2A, ( byte ) 0x86, 0x48, ( byte ) 0x86, ( byte ) 0xF7, 0x12, 0x01, 0x02, 0x02 };
        String string = new String( "1.2.840.113554.1.2.2" );

        long start = System.nanoTime();
        for ( int i = 0; i < 1000; i++ )
        {
            Arrays.equals( bytes, bytes );
        }
        logger.debug( "byte[]: {}", ( System.nanoTime() - start ) );

        start = System.nanoTime();
        for ( int i = 0; i < 1000; i++ )
        {
            string.equals( string );
        }
        logger.debug( "String: {}", ( System.nanoTime() - start ) );
    }


    @Test
    public void fromBytes() throws DecoderException
    {
        // first byte
        for ( int i = 0; i < 2; i++ )
        { // [0..2]
            for ( int j = 0; j < 40; j++ )
            { // [0..39]
                assertEquals( i + "." + j,
                    Oid.fromBytes( new byte[]
                        { ( byte ) ( i * 40 + j ) } )
                        .toString() );
            }
        }

        assertEquals( "1.2.840.113554.1.2.2",
            Oid.fromBytes( new byte[]
                {
                    0x2A, ( byte ) 0x86, 0x48, ( byte ) 0x86, ( byte ) 0xF7, 0x12, 0x01, 0x02, 0x02
            } ).toString() );

        assertEquals( "2.123456",
            Oid.fromBytes( new byte[]
                { ( byte ) 0x87, ( byte ) 0xC5, 0x10 } ).toString() );

    }


    @Test
    public void test2dot123456() throws DecoderException
    {
        String expectedString = "2.123456";
        byte[] expectedBytes = new byte[]
            { ( byte ) 0x87, ( byte ) 0xC5, 0x10 };

        logger.debug( "b_to_b: " + Arrays.toString( Oid.fromBytes( expectedBytes ).toBytes() ) );
        assertTrue( Arrays.equals( expectedBytes, Oid.fromBytes( expectedBytes ).toBytes() ) );

        logger.debug( "s_to_b: " + Arrays.toString( Oid.fromString( expectedString ).toBytes() ) );
        assertTrue( Arrays.equals( expectedBytes, Oid.fromString( expectedString ).toBytes() ) );

        logger.debug( "b_to_s: " + Oid.fromBytes( expectedBytes ).toString() );
        assertEquals( expectedString, Oid.fromBytes( expectedBytes ).toString() );

        logger.debug( "s_to_s: " + Oid.fromString( expectedString ).toString() );
        assertEquals( expectedString, Oid.fromString( expectedString ).toString() );
    }


    @Test
    public void fromString() throws DecoderException
    {
        // first byte
        for ( int i = 0; i < 2; i++ )
        { // [0..2]
            for ( int j = 0; j < 40; j++ )
            { // [0..39]
                assertTrue( Arrays.equals( new byte[]
                    { ( byte ) ( i * 40 + j ) },
                    Oid.fromString( i + "." + j ).toBytes() ) );
            }
        }

        assertTrue( Arrays.equals(
            new byte[]
                { 0x2A, ( byte ) 0x86, 0x48, ( byte ) 0x86, ( byte ) 0xF7, 0x12, 0x01, 0x02, 0x02 },
            Oid.fromString( "1.2.840.113554.1.2.2" ).toBytes() ) );
    }


    /**
     * Test a null NewOid
     */
    @Test
    public void testNewOidNull()
    {
        try
        {
            Oid.fromBytes( ( byte[] ) null );
            fail( "Should not reach this point ..." );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
        }
    }


    /**
     * Test an empty NewOid
     */
    @Test
    public void testNewOidEmpty()
    {
        try
        {
            Oid.fromBytes( new byte[]
                {} );
            fail( "Should not reach this point ..." );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
        }
    }


    /**
     * Test itu-t NewOid tree
     */
    @Test
    public void testNewOidItuT()
    {
        try
        {
            Oid oid = null;

            // itu-t(0), recommendation(0), series a-z (0..26)
            for ( int i = 1; i < 27; i++ )
            {
                oid = Oid.fromBytes( new byte[]
                    { 0x00, ( byte ) i } );
                assertEquals( "0.0." + i, oid.toString() );
            }

            // itu-t(0), question(1)
            oid = Oid.fromBytes( new byte[]
                { 0x01 } );
            assertEquals( "0.1", oid.toString() );

            // itu-t(0), administration(2), country(202 .. 748)
            for ( int i = 202; i < 748; i++ )
            {
                oid = Oid.fromBytes( new byte[]
                    { 0x02, ( byte ) ( ( i / 128 ) | 0x0080 ), ( byte ) ( i % 128 ) } );
                assertEquals( "0.2." + i, oid.toString() );
            }

            // itu-t(0), network-operator(3), operator(2023 .. 41363)
            for ( int i = 2023; i < 41363; i++ )
            {
                if ( i < ( 128 * 128 ) )
                {
                    oid = Oid.fromBytes( new byte[]
                        { 0x03, ( byte ) ( ( i / 128 ) | 0x0080 ), ( byte ) ( i % 128 ) } );
                    assertEquals( "0.3." + i, oid.toString() );
                }
                else
                {
                    oid = Oid.fromBytes( new byte[]
                        { 0x03, ( byte ) ( ( i / ( 128 * 128 ) ) | 0x0080 ),
                            ( byte ) ( ( ( i / 128 ) % 128 ) | 0x0080 ), ( byte ) ( i % 128 ) } );
                    assertEquals( "0.3." + i, oid.toString() );
                }
            }
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test iso NewOid tree
     */
    @Test
    public void testNewOidIso()
    {

        Oid oid = null;

        try
        {
            // iso(1), standard(0)
            oid = Oid.fromBytes( new byte[]
                { 40 + 0 } );
            assertEquals( "1.0", oid.toString() );

            // iso(1), registration-authority(1)
            oid = Oid.fromBytes( new byte[]
                { 40 + 1 } );
            assertEquals( "1.1", oid.toString() );

            // iso(1), member-body(2)
            oid = Oid.fromBytes( new byte[]
                { 40 + 2 } );
            assertEquals( "1.2", oid.toString() );

            // iso(1), identified-organization(3) | org(3) | organization(3)
            oid = Oid.fromBytes( new byte[]
                { 40 + 3 } );
            assertEquals( "1.3", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test joint-iso-itu-t NewOid tree
     */
    @Test
    public void testNewOidJointIsoItuT()
    {
        Oid oid = null;

        try
        {
            // joint-iso-itu-t(2), presentation(0)
            oid = Oid.fromBytes( new byte[]
                { 80 + 0 } );
            assertEquals( "2.0", oid.toString() );

            // joint-iso-itu-t(2), asn1(1)
            oid = Oid.fromBytes( new byte[]
                { 80 + 1 } );
            assertEquals( "2.1", oid.toString() );

            // joint-iso-itu-t(2), association-control(2)
            oid = Oid.fromBytes( new byte[]
                { 80 + 2 } );
            assertEquals( "2.2", oid.toString() );

            // joint-iso-itu-t(2), reliable-transfer(3)
            oid = Oid.fromBytes( new byte[]
                { 80 + 3 } );
            assertEquals( "2.3", oid.toString() );

            // ...
            // joint-iso-itu-t(2), upu(40)
            oid = Oid.fromBytes( new byte[]
                { 80 + 40 } );
            assertEquals( "2.40", oid.toString() );

            // ...
            // joint-iso-itu-t(2), xxx(100)
            oid = Oid.fromBytes( new byte[]
                { ( byte ) ( 0x81 ), 0x34 } );
            assertEquals( "2.100", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test valid String NewOids
     */
    @Test
    public void testNewOidStringGood()
    {
        Oid oid = null;

        try
        {
            oid = Oid.fromString( "0.0" );
            assertEquals( "0.0", oid.toString() );

            oid = Oid.fromString( "0.0.0.0.0" );
            assertEquals( "0.0.0.0.0", oid.toString() );

            oid = Oid.fromString( "0.1.2.3.4" );
            assertEquals( "0.1.2.3.4", oid.toString() );

            oid = Oid.fromString( "2.123456" );
            assertEquals( "2.123456", oid.toString() );

            oid = Oid.fromString( "1.2.840.113554.1.2.2" );
            assertEquals( "1.2.840.113554.1.2.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test invalid String NewOids
     */
    @Test
    public void testNewOidStringBad()
    {
        assertFalse( Oid.isOid( "0" ) );
        assertFalse( Oid.isOid( "0." ) );
        assertFalse( Oid.isOid( "." ) );
        assertFalse( Oid.isOid( "0.1.2." ) );
        assertFalse( Oid.isOid( "3.1" ) );
        assertFalse( Oid.isOid( "0..1" ) );
        assertFalse( Oid.isOid( "0..12" ) );
        assertFalse( Oid.isOid( "0.a.2" ) );
        assertFalse( Oid.isOid( "0.123456" ) );
        assertFalse( Oid.isOid( "1.123456" ) );
    }


    /**
     * Test Spnego NewOid
     */
    @Test
    public void testNewOidSpnego()
    {
        Oid oid = null;

        try
        {
            oid = Oid.fromBytes( new byte[]
                { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 } );
            assertEquals( "1.3.6.1.5.5.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test Kerberos V5 NewOid
     */
    @Test
    public void testNewOidKerberosV5()
    {
        Oid oid = null;

        try
        {
            oid = Oid.fromBytes( new byte[]
                { 0x2a, ( byte ) 0x86, 0x48, ( byte ) 0x86, ( byte ) 0xf7, 0x12, 0x01, 0x02, 0x02 } );
            assertEquals( "1.2.840.113554.1.2.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test NewOids bytes
     */
    @Test
    public void testNewOidBytes()
    {
        Oid oid = null;
        Oid oid2 = null;

        try
        {
            oid = Oid.fromString( "0.0" );
            oid2 = Oid.fromBytes( oid.toBytes() );
            assertEquals( oid.toString(), oid2.toString() );

            oid = Oid.fromString( "0.0.0.0.0" );
            oid2 = Oid.fromBytes( oid.toBytes() );
            assertEquals( oid.toString(), oid2.toString() );

            oid = Oid.fromString( "0.1.2.3.4" );
            assertTrue( Arrays.equals( new byte[]
                { 0x01, 0x02, 0x03, 0x04 }, oid.toBytes() ) );
            oid2 = Oid.fromBytes( oid.toBytes() );
            assertEquals( oid.toString(), oid2.toString() );

            oid = Oid.fromString( "2.123456" );
            oid2 = Oid.fromBytes( oid.toBytes() );
            assertEquals( oid.toString(), oid2.toString() );

            oid = Oid.fromString( "1.2.840.113554.1.2.2" );
            oid2 = Oid.fromBytes( oid.toBytes() );
            assertEquals( oid.toString(), oid2.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test NewOid Equals
     */
    @Test
    public void testNewOidEqualsPerf() throws DecoderException
    {
        String s1 = "1.2.840.113554.1.2.2.1.2.840.113554.1.2.2.1.2.840.113554.1.2.2";
        String s2 = "1.2.840.113554.1.2.2.1.2.840.113554.1.2.2.1.2.840.113554.1.2.2";
        String s3 = "1.3.6.1.5.5.2";

        Oid oid1 = Oid.fromString( s1 );
        Oid oid2 = Oid.fromString( s2 );
        Oid oid3 = Oid.fromString( s3 );

        assertTrue( oid1.equals( oid2 ) );
        assertFalse( oid1.equals( oid3 ) );
        assertFalse( oid2.equals( oid3 ) );
    }
}
