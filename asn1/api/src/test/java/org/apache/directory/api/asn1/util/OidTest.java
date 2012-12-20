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

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the Oid primitive
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class OidTest
{
    /**
     * Test a null Oid
     */
    @Test
    public void testOidNull()
    {

        Oid oid = new Oid();

        try
        {
            oid.setOid( ( byte[] ) null );
            fail( "Should not reach this point ..." );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
        }
    }


    /**
     * Test an empty Oid
     */
    @Test
    public void testOidEmpty()
    {

        Oid oid = new Oid();

        try
        {
            oid.setOid( new byte[]
                {} );
            fail( "Should not reach this point ..." );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
        }
    }


    /**
     * Test itu-t Oid tree
     */
    @Test
    public void testOidItuT()
    {

        Oid oid = new Oid();

        try
        {

            // itu-t(0), recommendation(0), series a-z (0..26)
            for ( int i = 1; i < 27; i++ )
            {
                oid.setOid( new byte[]
                    { 0x00, ( byte ) i } );
                assertEquals( "0.0." + i, oid.toString() );
            }

            // itu-t(0), question(1)
            oid.setOid( new byte[]
                { 0x01 } );
            assertEquals( "0.1", oid.toString() );

            // itu-t(0), administration(2), country(202 .. 748)
            for ( int i = 202; i < 748; i++ )
            {
                oid.setOid( new byte[]
                    { 0x02, ( byte ) ( ( i / 128 ) | 0x0080 ), ( byte ) ( i % 128 ) } );
                assertEquals( "0.2." + i, oid.toString() );
            }

            // itu-t(0), network-operator(3), operator(2023 .. 41363)
            for ( int i = 2023; i < 41363; i++ )
            {

                if ( i < ( 128 * 128 ) )
                {
                    oid.setOid( new byte[]
                        { 0x03, ( byte ) ( ( i / 128 ) | 0x0080 ), ( byte ) ( i % 128 ) } );
                    assertEquals( "0.3." + i, oid.toString() );
                }
                else
                {
                    oid.setOid( new byte[]
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
     * Test iso Oid tree
     */
    @Test
    public void testOidIso()
    {

        Oid oid = new Oid();

        try
        {

            // iso(1), standard(0)
            oid.setOid( new byte[]
                { 40 + 0 } );
            assertEquals( "1.0", oid.toString() );

            // iso(1), registration-authority(1)
            oid.setOid( new byte[]
                { 40 + 1 } );
            assertEquals( "1.1", oid.toString() );

            // iso(1), member-body(2)
            oid.setOid( new byte[]
                { 40 + 2 } );
            assertEquals( "1.2", oid.toString() );

            // iso(1), identified-organization(3) | org(3) | organization(3)
            oid.setOid( new byte[]
                { 40 + 3 } );
            assertEquals( "1.3", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test joint-iso-itu-t Oid tree
     */
    @Test
    public void testOidJointIsoItuT()
    {

        Oid oid = new Oid();

        try
        {

            // joint-iso-itu-t(2), presentation(0)
            oid.setOid( new byte[]
                { 80 + 0 } );
            assertEquals( "2.0", oid.toString() );

            // joint-iso-itu-t(2), asn1(1)
            oid.setOid( new byte[]
                { 80 + 1 } );
            assertEquals( "2.1", oid.toString() );

            // joint-iso-itu-t(2), association-control(2)
            oid.setOid( new byte[]
                { 80 + 2 } );
            assertEquals( "2.2", oid.toString() );

            // joint-iso-itu-t(2), reliable-transfer(3)
            oid.setOid( new byte[]
                { 80 + 3 } );
            assertEquals( "2.3", oid.toString() );

            // ...
            // joint-iso-itu-t(2), upu(40)
            oid.setOid( new byte[]
                { 80 + 40 } );
            assertEquals( "2.40", oid.toString() );

            // ...
            // joint-iso-itu-t(2), xxx(100)
            oid.setOid( new byte[]
                { ( byte ) ( 0x81 ), 0x34 } );
            assertEquals( "2.100", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test valid String Oids
     */
    @Test
    public void testOidStringGood()
    {

        Oid oid = new Oid();

        try
        {
            oid.setOid( "0.0" );
            assertEquals( "0.0", oid.toString() );

            oid.setOid( "0.0.0.0.0" );
            assertEquals( "0.0.0.0.0", oid.toString() );

            oid.setOid( "0.1.2.3.4" );
            assertEquals( "0.1.2.3.4", oid.toString() );

            oid.setOid( "2.123456" );
            assertEquals( "2.123456", oid.toString() );

            oid.setOid( "1.2.840.113554.1.2.2" );
            assertEquals( "1.2.840.113554.1.2.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test invalid String Oids
     */
    @Test
    public void testOidStringBad()
    {
        assertFalse( Oid.isOid( "0" ) );
        assertFalse( Oid.isOid( "0." ) );
        assertFalse( Oid.isOid( "." ) );
        assertFalse( Oid.isOid( "0.1.2." ) );
        assertFalse( Oid.isOid( "3.1" ) );
        assertFalse( Oid.isOid( "0..1" ) );
        assertFalse( Oid.isOid( "0..12" ) );
        assertFalse( Oid.isOid( "0.a.2" ) );
        assertTrue( Oid.isOid( "0.123456" ) );
        assertTrue( Oid.isOid( "1.123456" ) );
    }


    /**
     * Test Spnego Oid
     */
    @Test
    public void testOidSpnego()
    {

        Oid oid = new Oid();

        try
        {
            oid.setOid( new byte[]
                { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 } );

            assertEquals( "1.3.6.1.5.5.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test Kerberos V5 Oid
     */
    @Test
    public void testOidKerberosV5()
    {

        Oid oid = new Oid();

        try
        {
            oid.setOid( new byte[]
                { 0x2a, ( byte ) 0x86, 0x48, ( byte ) 0x86, ( byte ) 0xf7, 0x12, 0x01, 0x02, 0x02 } );

            assertEquals( "1.2.840.113554.1.2.2", oid.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test Oids bytes
     */
    @Test
    public void testOidBytes()
    {
        Oid oid = new Oid();
        Oid oid2 = new Oid();

        try
        {
            oid.setOid( "0.0" );
            oid2.setOid( oid.getOid() );
            assertEquals( oid.toString(), oid2.toString() );

            oid.setOid( "0.0.0.0.0" );
            oid2.setOid( oid.getOid() );
            assertEquals( oid.toString(), oid2.toString() );

            oid.setOid( "0.1.2.3.4" );
            oid2.setOid( oid.getOid() );
            assertEquals( oid.toString(), oid2.toString() );

            oid.setOid( "2.123456" );
            oid2.setOid( oid.getOid() );
            assertEquals( oid.toString(), oid2.toString() );

            oid.setOid( "1.2.840.113554.1.2.2" );
            oid2.setOid( oid.getOid() );
            assertEquals( oid.toString(), oid2.toString() );
        }
        catch ( DecoderException de )
        {
            fail();
        }
    }


    /**
     * Test Oid Equals
     */
    @Test
    public void testOidEquals() throws DecoderException
    {
        Oid oid1 = new Oid();
        Oid oid2 = new Oid();
        Oid oid3 = new Oid( "1.1" );

        assertTrue( oid1.equals( oid2 ) );
        assertFalse( oid1.equals( oid3 ) );
        assertFalse( oid2.equals( oid3 ) );
    }


    /**
     * Test Oid Equals
     */
    @Test
    public void testOidEqualsPerf() throws DecoderException
    {
        String s1 = "1.2.840.113554.1.2.2.1.2.840.113554.1.2.2.1.2.840.113554.1.2.2";
        String s2 = "1.2.840.113554.1.2.2.1.2.840.113554.1.2.2.1.2.840.113554.1.2.2";
        String s3 = "1.3.6.1.5.5.2";

        Oid oid1 = new Oid( s1 );
        Oid oid2 = new Oid( s2 );
        Oid oid3 = new Oid( s3 );

        assertTrue( oid1.equals( oid2 ) );
        assertFalse( oid1.equals( oid3 ) );
        assertFalse( oid2.equals( oid3 ) );
    }
}
