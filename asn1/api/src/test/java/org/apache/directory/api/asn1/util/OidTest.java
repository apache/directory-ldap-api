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


/**
 * A test class for the Oid class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OidTest
{
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
    public void fromBytesLongValues() throws DecoderException
    {
        // 2.0 -> expected 0x02
        assertEquals( "2.0", Oid.fromBytes( new byte[] { 0x50 } ).toString() );
        
        // 2.40 -> expected 0x78
        assertEquals( "2.40", Oid.fromBytes( new byte[] { 0x78 } ).toString() );
        
        // 2.48 -> expected 0x81 0x00
        assertEquals( "2.48", Oid.fromBytes( new byte[] { (byte)0x81, 0x00 } ).toString() );
        
        // The second arc is below and equal to 16304 : 0x4000 - 0x50
        assertEquals( "2.16303", Oid.fromBytes( new byte[] { (byte)0xFF, 0x7F } ).toString() );
        assertEquals( "2.16304", Oid.fromBytes( new byte[] { (byte)0x81, (byte)0x80, 0x00 } ).toString() );
        
        // The second arc is below and equal to 2097072 : 0x200000 - 0x50
        assertEquals( "2.2097071", Oid.fromBytes( new byte[] { (byte)0xFF, (byte)0xFF, 0x7F } ).toString() );
        assertEquals( "2.2097072", Oid.fromBytes( new byte[] { (byte)0x81, (byte)0x80, (byte)0x80, 0x00 } ).toString() );

        // The second arc is below and equal to 268435376 : 0x10000000 - 0x50
        assertEquals( "2.268435375", Oid.fromBytes( new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, 0x7F } ).toString() );
        assertEquals( "2.268435376", 
            Oid.fromBytes( new byte[] 
                { 
                    (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                    0x00 
                } ).toString() );
        
        // The second arc is below and equal to 34359738288 : 0x800000000 - 0x50
        Oid oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 0x7F 
            } );
        assertEquals( "2.34359738287", oid.toString() );
        Oid oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );
        
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, 0x00 
            } );
        assertEquals( "2.34359738288", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 4398046511024 : 0x40000000000 - 0x50
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, 0x7F 
            } );
        assertEquals( "2.4398046511023", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );
        
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, (byte)0x80, 0x00 
            } ); 
        assertEquals( "2.4398046511024", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 562949953421232 : 0x2000000000000 - 0x50
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, 0x7F 
            } ); 
        assertEquals( "2.562949953421231", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, (byte)0x80, (byte)0x80, 0x00 
            } ); 
        assertEquals( "2.562949953421232", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 72057594037927856 : 0x100000000000000 - 0x50
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, 0x7F 
            } ); 
        assertEquals( "2.72057594037927855", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, (byte)0x80, (byte)0x80, (byte)0x80, 
                0x00 
            } ); 
        assertEquals( "2.72057594037927856", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 9223372036854775728 : 0x8000000000000000 - 0x50
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                0x7F 
            } ); 
        assertEquals( "2.9223372036854775727", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, (byte)0x80, (byte)0x80, (byte)0x80, 
                (byte)0x80, 0x00 
            } ); 
        assertEquals( "2.9223372036854775728", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // Check for 9999999999999999999 which is higher than Long.MAX_VALUE
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0x81, (byte)0x8A, (byte)0xE3, (byte)0xC8, 
                (byte)0xE0, (byte)0xC8, (byte)0xCF, (byte)0xA0, 
                (byte)0x80, 0x4F 
            } );
        assertEquals( "2.9999999999999999999", oid.toString() ) ;
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );

        // A bigger one
        oid = Oid.fromBytes( new byte[] 
            { 
                (byte)0xFA, (byte)0xBE, (byte)0xB7, (byte)0xA2, 
                (byte)0x8E, (byte)0xF4, (byte)0xC0, (byte)0xC7, 
                (byte)0xCB, (byte)0x9F, (byte)0xA0, (byte)0xC5, 
                (byte)0xEA, (byte)0xDA, (byte)0x92, (byte)0x9D, 
                (byte)0x9E, 0x0C
            } ); 
        assertEquals( "2.81407072025111374527560065493494091452", oid.toString() );
        oid1 = Oid.fromString( oid.toString() );
        assertEquals( oid, oid1 );
    }


    @Test
    public void test2dot123456() throws DecoderException
    {
        String expectedString = "2.123456";
        byte[] expectedBytes = new byte[]
            { ( byte ) 0x87, ( byte ) 0xC5, 0x10 };

        assertTrue( Arrays.equals( expectedBytes, Oid.fromBytes( expectedBytes ).toBytes() ) );

        assertTrue( Arrays.equals( expectedBytes, Oid.fromString( expectedString ).toBytes() ) );

        assertEquals( expectedString, Oid.fromBytes( expectedBytes ).toString() );

        assertEquals( expectedString, Oid.fromString( expectedString ).toString() );
    }

    
    /** Hex chars */
    private static final byte[] HEX_CHAR = new byte[]
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Helper function that dump an array of bytes in hex form
     *
     * @param buffer The bytes array to dump
     * @return A string representation of the array of bytes
     */
    public static String dumpBytes( byte[] buffer )
    {
        if ( buffer == null )
        {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for ( int i = 0; i < buffer.length; i++ )
        {
            sb.append( "0x" ).append( ( char ) ( HEX_CHAR[( buffer[i] & 0x00F0 ) >> 4] ) ).append(
                ( char ) ( HEX_CHAR[buffer[i] & 0x000F] ) ).append( " " );
        }

        return sb.toString();
    }


    @Test
    public void fromString() throws DecoderException
    {
        // first byte
        for ( int i = 0; i < 2; i++ )
        { // [0..2]
            for ( int j = 0; j < 40; j++ )
            { // [0..39]
                String oidStr = i + "." + j;
                byte[] expected = new byte[]{ ( byte ) ( i * 40 + j ) };
                byte[] oidBytes = Oid.fromString( oidStr ).toBytes();
                assertTrue( Arrays.equals( expected, oidBytes ) );
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
        assertFalse( Oid.isOid( "1" ) );
        assertFalse( Oid.isOid( "0." ) );
        assertFalse( Oid.isOid( "1." ) );
        assertFalse( Oid.isOid( "2." ) );
        assertFalse( Oid.isOid( "2." ) );
        assertFalse( Oid.isOid( "." ) );
        assertFalse( Oid.isOid( "0.1.2." ) );
        assertFalse( Oid.isOid( "3.1" ) );
        assertFalse( Oid.isOid( "0..1" ) );
        assertFalse( Oid.isOid( "0..12" ) );
        assertFalse( Oid.isOid( "0.a.2" ) );
        assertFalse( Oid.isOid( "0.40" ) );
        assertFalse( Oid.isOid( "0.51" ) );
        assertFalse( Oid.isOid( "0.01" ) );
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
     * Test an OID with a node which does not fit in a long
     * @throws DecoderException 
     */
    @Test
    public void testOidLongValue() throws DecoderException
    {
        // 2.0 -> expected 0x02
        Oid oid = Oid.fromString( "2.0" );
        byte[] oidBytes = oid.toBytes();
        assertEquals( 1, oidBytes.length );
        assertEquals( 80, oidBytes[0] );
        Oid oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );
        
        // 2.40 -> expected 0x78
        oid = Oid.fromString( "2.40" );
        oidBytes = oid.toBytes();
        assertEquals( 1, oidBytes.length );
        assertEquals( 0x78, oidBytes[0] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );
        
        // 2.48 -> expected 0x80
        oid = Oid.fromString( "2.48" );
        oidBytes = oid.toBytes();
        assertEquals( 2, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( 0x00, oidBytes[1] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );
        
        // The second arc is below and equal to 16304 : 0x4000 - 0x50
        oid = Oid.fromString( "2.16303" );
        oidBytes = oid.toBytes();
        assertEquals( 2, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( 0x7F, oidBytes[1] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.16304" );
        oidBytes = oid.toBytes();
        assertEquals( 3, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( 0x00, oidBytes[2] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );
        
        // The second arc is below and equal to 2097072 : 0x200000 - 0x50
        oid = Oid.fromString( "2.2097071" );
        oidBytes = oid.toBytes();
        assertEquals( 3, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( 0x7F, oidBytes[2] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.2097072" );
        oidBytes = oid.toBytes();
        assertEquals( 4, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( 0x00, oidBytes[3] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 268435376 : 0x10000000 - 0x50
        oid = Oid.fromString( "2.268435375" );
        oidBytes = oid.toBytes();
        assertEquals( 4, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( 0x7F, oidBytes[3] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.268435376" );
        oidBytes = oid.toBytes();
        assertEquals( 5, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( 0x00, oidBytes[4] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 34359738288 : 0x800000000 - 0x50
        oid = Oid.fromString( "2.34359738287" );
        oidBytes = oid.toBytes();
        assertEquals( 5, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( (byte)0xFF, oidBytes[3] );
        assertEquals( 0x7F, oidBytes[4] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.34359738288" );
        oidBytes = oid.toBytes();
        assertEquals( 6, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( (byte)0x80, oidBytes[4] );
        assertEquals( 0x00, oidBytes[5] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 4398046511024 : 0x40000000000 - 0x50
        oid = Oid.fromString( "2.4398046511023" );
        oidBytes = oid.toBytes();
        assertEquals( 6, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( (byte)0xFF, oidBytes[3] );
        assertEquals( (byte)0xFF, oidBytes[4] );
        assertEquals( 0x7F, oidBytes[5] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.4398046511024" );
        oidBytes = oid.toBytes();
        assertEquals( 7, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( (byte)0x80, oidBytes[4] );
        assertEquals( (byte)0x80, oidBytes[5] );
        assertEquals( 0x00, oidBytes[6] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 562949953421232 : 0x2000000000000 - 0x50
        oid = Oid.fromString( "2.562949953421231" );
        oidBytes = oid.toBytes();
        assertEquals( 7, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( (byte)0xFF, oidBytes[3] );
        assertEquals( (byte)0xFF, oidBytes[4] );
        assertEquals( (byte)0xFF, oidBytes[5] );
        assertEquals( 0x7F, oidBytes[6] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.562949953421232" );
        oidBytes = oid.toBytes();
        assertEquals( 8, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( (byte)0x80, oidBytes[4] );
        assertEquals( (byte)0x80, oidBytes[5] );
        assertEquals( (byte)0x80, oidBytes[6] );
        assertEquals( 0x00, oidBytes[7] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 72057594037927856 : 0x100000000000000 - 0x50
        oid = Oid.fromString( "2.72057594037927855" );
        oidBytes = oid.toBytes();
        assertEquals( 8, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( (byte)0xFF, oidBytes[3] );
        assertEquals( (byte)0xFF, oidBytes[4] );
        assertEquals( (byte)0xFF, oidBytes[5] );
        assertEquals( (byte)0xFF, oidBytes[6] );
        assertEquals( 0x7F, oidBytes[7] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.72057594037927856" );
        oidBytes = oid.toBytes();
        assertEquals( 9, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( (byte)0x80, oidBytes[4] );
        assertEquals( (byte)0x80, oidBytes[5] );
        assertEquals( (byte)0x80, oidBytes[6] );
        assertEquals( (byte)0x80, oidBytes[7] );
        assertEquals( 0x00, oidBytes[8] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // The second arc is below and equal to 9223372036854775728 : 0x8000000000000000 - 0x50
        oid = Oid.fromString( "2.9223372036854775727" );
        oidBytes = oid.toBytes();
        assertEquals( 9, oidBytes.length );
        assertEquals( (byte)0xFF, oidBytes[0] );
        assertEquals( (byte)0xFF, oidBytes[1] );
        assertEquals( (byte)0xFF, oidBytes[2] );
        assertEquals( (byte)0xFF, oidBytes[3] );
        assertEquals( (byte)0xFF, oidBytes[4] );
        assertEquals( (byte)0xFF, oidBytes[5] );
        assertEquals( (byte)0xFF, oidBytes[6] );
        assertEquals( (byte)0xFF, oidBytes[6] );
        assertEquals( (byte)0xFF, oidBytes[7] );
        assertEquals( 0x7F, oidBytes[8] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        oid = Oid.fromString( "2.9223372036854775728" );
        oidBytes = oid.toBytes();
        assertEquals( 10, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x80, oidBytes[1] );
        assertEquals( (byte)0x80, oidBytes[2] );
        assertEquals( (byte)0x80, oidBytes[3] );
        assertEquals( (byte)0x80, oidBytes[4] );
        assertEquals( (byte)0x80, oidBytes[5] );
        assertEquals( (byte)0x80, oidBytes[6] );
        assertEquals( (byte)0x80, oidBytes[7] );
        assertEquals( (byte)0x80, oidBytes[8] );
        assertEquals( 0x00, oidBytes[9] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // Check for 9999999999999999999 which is higher than Long.MAX_VALUE
        oid = Oid.fromString( "2.9999999999999999999" );
        oidBytes = oid.toBytes();
        assertEquals( 10, oidBytes.length );
        assertEquals( (byte)0x81, oidBytes[0] );
        assertEquals( (byte)0x8A, oidBytes[1] );
        assertEquals( (byte)0xE3, oidBytes[2] );
        assertEquals( (byte)0xC8, oidBytes[3] );
        assertEquals( (byte)0xE0, oidBytes[4] );
        assertEquals( (byte)0xC8, oidBytes[5] );
        assertEquals( (byte)0xCF, oidBytes[6] );
        assertEquals( (byte)0xA0, oidBytes[7] );
        assertEquals( (byte)0x80, oidBytes[8] );
        assertEquals( (byte)0x4F, oidBytes[9] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );

        // A bigger one
        oid = Oid.fromString( "2.81407072025111374527560065493494091452" );
        oidBytes = oid.toBytes();
        assertEquals( 18, oidBytes.length );
        assertEquals( (byte)0xFA, oidBytes[0] );
        assertEquals( (byte)0xBE, oidBytes[1] );
        assertEquals( (byte)0xB7, oidBytes[2] );
        assertEquals( (byte)0xA2, oidBytes[3] );
        assertEquals( (byte)0x8E, oidBytes[4] );
        assertEquals( (byte)0xF4, oidBytes[5] );
        assertEquals( (byte)0xC0, oidBytes[6] );
        assertEquals( (byte)0xC7, oidBytes[7] );
        assertEquals( (byte)0xCB, oidBytes[8] );
        assertEquals( (byte)0x9F, oidBytes[9] );
        assertEquals( (byte)0xA0, oidBytes[10] );
        assertEquals( (byte)0xC5, oidBytes[11] );
        assertEquals( (byte)0xEA, oidBytes[12] );
        assertEquals( (byte)0xDA, oidBytes[13] );
        assertEquals( (byte)0x92, oidBytes[14] );
        assertEquals( (byte)0x9D, oidBytes[15] );
        assertEquals( (byte)0x9E, oidBytes[16] );
        assertEquals( (byte)0x0C, oidBytes[17] );
        oid1 = Oid.fromBytes( oidBytes );
        assertEquals( oid, oid1 );
    }


    /**
     * Test an OID with 2 at the first position and a second node > 39
     * @throws DecoderException 
     */
    @Test
    public void testOidNode2() throws DecoderException
    {
        Oid oid = Oid.fromString( "2.12345" );
        Oid oid2 = Oid.fromBytes( oid.toBytes() );
        assertEquals( oid, oid2 );
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

            oid = Oid.fromString( "1.2.3.4.5" );
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
